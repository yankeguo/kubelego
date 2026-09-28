// Package acme issues certificates with the lego library using DNS-01.
package acme

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	legocme "github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"

	"github.com/yankeguo/kubelego/internal/state"
)

// Client is a lego-backed issuer. DNS provider credentials are read from the
// environment variables documented by that provider.
type Client struct {
	Provider  string
	Resolvers []string
	Timeout   time.Duration

	once sync.Once
}

// EnsureAccount creates or updates the ACME account stored in st.
// The account key is saved before registration, and the registration is saved
// before EnsureAccount returns, so a restart keeps the same account.
func (c *Client) EnsureAccount(ctx context.Context, st *state.State, email, server, kid, hmac string, save func(context.Context, *state.State) error) error {
	if save == nil {
		return errors.New("state save function is not configured")
	}
	hadOrder := st.Order != nil
	plan, err := planAccount(st, email, server)
	if err != nil {
		return err
	}
	if hadOrder && st.Order == nil {
		slog.Warn("dropped in-progress order while preparing the account")
	}
	if plan.saveBeforeNetwork {
		if err := save(ctx, st); err != nil {
			return fmt.Errorf("save account: %w", err)
		}
	}

	if plan.register {
		account, err := c.user(st)
		if err != nil {
			return err
		}
		client, err := newClient(account, st.Server)
		if err != nil {
			return err
		}
		reg, err := register(ctx, client, st.Server, st.Email, kid, hmac)
		if err != nil {
			return err
		}
		st.Registration = reg
		if err := save(ctx, st); err != nil {
			return fmt.Errorf("save account: %w", err)
		}
		return nil
	}

	if plan.updateEmail {
		previous := st.Email
		st.Email = email
		account, err := c.user(st)
		if err != nil {
			st.Email = previous
			return err
		}
		client, err := newClient(account, st.Server)
		if err != nil {
			st.Email = previous
			return err
		}
		reg, err := client.Registration.UpdateRegistration(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			st.Email = previous
			return fmt.Errorf("update account contact: %w", err)
		}
		st.Registration = reg
		if err := save(ctx, st); err != nil {
			return fmt.Errorf("save account: %w", err)
		}
	}
	return nil
}

func (c *Client) user(st *state.State) (*user, error) {
	key, err := certcrypto.ParsePEMPrivateKey(st.AccountKey)
	if err != nil {
		return nil, fmt.Errorf("parse account key: %w", err)
	}
	return &user{email: st.Email, key: key, reg: st.Registration}, nil
}

func (c *Client) prepareDNS() error {
	c.once.Do(func() {
		if len(c.Resolvers) == 0 {
			return
		}
		opts := dns01.NewOptions()
		opts.RecursiveNameservers = append([]string(nil), c.Resolvers...)
		dns01.SetDefaultClient(dns01.NewClient(opts))
	})
	return nil
}

func newClient(account registration.User, server string) (*lego.Client, error) {
	cfg := lego.NewConfig(account)
	cfg.CADirURL = server
	cfg.UserAgent = "kubelego"
	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("acme client: %w", err)
	}
	return client, nil
}

func register(ctx context.Context, client *lego.Client, server, email, kid, hmac string) (*legocme.ExtendedAccount, error) {
	if kid != "" {
		reg, err := client.Registration.RegisterWithExternalAccountBinding(ctx, registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  kid,
			HmacEncoded:          hmac,
		})
		if err != nil {
			return nil, fmt.Errorf("register account: %w", err)
		}
		return reg, nil
	}
	if strings.Contains(server, "zerossl.com") {
		reg, err := registration.RegisterWithZeroSSL(ctx, client.Registration, email)
		if err != nil {
			return nil, fmt.Errorf("register zerossl account: %w", err)
		}
		return reg, nil
	}
	reg, err := client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("register account: %w", err)
	}
	return reg, nil
}
