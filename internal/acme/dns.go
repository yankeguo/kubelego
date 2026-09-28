package acme

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/providers/dns"
)

type sequencer interface {
	Sequential() time.Duration
}

func (c *Client) dnsProvider() (challenge.Provider, bool, time.Duration, error) {
	// Same factory as the lego CLI, including every built-in provider and alias.
	// Provider credentials stay in that provider's own environment variables.
	provider, err := dns.NewDNSChallengeProviderByName(c.Provider)
	if err != nil {
		return nil, false, 0, fmt.Errorf("dns provider %q: %w", c.Provider, err)
	}
	sequential := false
	var seq time.Duration
	if s, ok := provider.(sequencer); ok {
		sequential = true
		seq = s.Sequential()
	}
	if c.Timeout <= 0 {
		return provider, sequential, seq, nil
	}
	interval := 2 * time.Second
	if c.Timeout < interval {
		interval = c.Timeout
	}
	return timeoutProvider{Provider: provider, timeout: c.Timeout, interval: interval}, sequential, seq, nil
}

func (c *Client) solveAuthorizations(ctx context.Context, core *api.Core, authzs []acme.Authorization) error {
	pending := make([]acme.Authorization, 0, len(authzs))
	for _, authz := range authzs {
		switch authz.Status {
		case acme.StatusValid:
			continue
		case "", acme.StatusPending, acme.StatusProcessing:
			pending = append(pending, authz)
		default:
			return fmt.Errorf("%w: %s is %s", errAuthorizationFailed, challenge.GetTargetedDomain(authz), authz.Status)
		}
	}
	if len(pending) == 0 {
		return nil
	}

	provider, sequential, seq, err := c.dnsProvider()
	if err != nil {
		return err
	}
	solver := dns01.NewChallenge(core, validateAuthorization, provider, dns01.WrapPreCheck(stopWhenCanceled))

	var presented []acme.Authorization
	defer func() { cleanAuthorizations(presented, solver) }()

	if sequential {
		for i, authz := range pending {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := presentAuthorization(ctx, solver, authz); err != nil {
				return err
			}
			presented = append(presented, authz)
			if err := solver.Solve(ctx, authz); err != nil {
				return err
			}
			cleanAuthorizations([]acme.Authorization{authz}, solver)
			if i < len(pending)-1 {
				if err := sleepCtx(ctx, seq); err != nil {
					return err
				}
			}
		}
		return nil
	}

	for _, authz := range pending {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := presentAuthorization(ctx, solver, authz); err != nil {
			return err
		}
		presented = append(presented, authz)
	}
	for _, authz := range pending {
		if err := solver.Solve(ctx, authz); err != nil {
			return err
		}
	}
	return nil
}

func presentAuthorization(ctx context.Context, solver *dns01.Challenge, authz acme.Authorization) error {
	// A killed process may have left the TXT record in place. Remove it before
	// writing so providers that reject duplicate names can present again.
	if err := solver.CleanUp(ctx, authz); err != nil {
		slog.Debug("dns cleanup before present", "domain", challenge.GetTargetedDomain(authz), "err", err)
	}
	if err := solver.PreSolve(ctx, authz); err != nil {
		return fmt.Errorf("present dns-01 for %s: %w", challenge.GetTargetedDomain(authz), err)
	}
	return nil
}

func cleanAuthorizations(authzs []acme.Authorization, solver *dns01.Challenge) {
	if len(authzs) == 0 || solver == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, authz := range authzs {
		if err := solver.CleanUp(ctx, authz); err != nil {
			slog.Warn("dns cleanup failed", "domain", challenge.GetTargetedDomain(authz), "err", err)
		}
	}
}

func stopWhenCanceled(ctx context.Context, _, fqdn, value string, check dns01.PreCheckFunc) (bool, error) {
	if err := ctx.Err(); err != nil {
		return true, err
	}
	ok, err := check(ctx, fqdn, value)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return true, ctxErr
	}
	return ok, err
}

func validateAuthorization(ctx context.Context, core *api.Core, domain string, chlng acme.Challenge) error {
	started, err := core.Challenges.New(ctx, chlng.URL)
	if err != nil {
		return fmt.Errorf("initiate challenge for %s: %w", domain, err)
	}
	switch started.Status {
	case acme.StatusValid:
		return nil
	case acme.StatusInvalid:
		return fmt.Errorf("%w: %s: %v", errAuthorizationFailed, domain, started.Error)
	}

	interval := started.RetryAfter
	if interval <= 0 {
		interval = 5 * time.Second
	}
	deadline := time.Now().Add(100 * interval)
	if started.AuthorizationURL == "" {
		return fmt.Errorf("challenge for %s has no authorization url", domain)
	}
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("authorization %s was not validated before the deadline", domain)
		}
		if err := sleepCtx(ctx, interval); err != nil {
			return err
		}
		authz, err := core.Authorizations.Get(ctx, started.AuthorizationURL)
		if err != nil {
			return fmt.Errorf("poll authorization for %s: %w", domain, err)
		}
		switch authz.Status {
		case acme.StatusValid:
			return nil
		case "", acme.StatusPending, acme.StatusProcessing:
			continue
		default:
			return fmt.Errorf("%w: %s is %s", errAuthorizationFailed, domain, authz.Status)
		}
	}
}
