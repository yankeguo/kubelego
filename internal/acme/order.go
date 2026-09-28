package acme

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/lego"

	"github.com/yankeguo/kubelego/internal/state"
)

const certificateWait = 30 * time.Second

var (
	errAuthorizationFailed = errors.New("authorization failed")
	errOrderInvalid        = errors.New("order is invalid")
)

// Issue creates or resumes the ACME order stored on st.
// The order, including its private key, is saved before DNS-01 starts.
// On failure the order is left in place unless the CA has rejected it or it
// no longer matches the requested certificate. A later call continues it.
func (c *Client) Issue(ctx context.Context, st *state.State, domains []string, keyType string, renew bool, save func(context.Context, *state.State) error) (state.Certificate, error) {
	if save == nil {
		return state.Certificate{}, errors.New("state save function is not configured")
	}
	if err := ctx.Err(); err != nil {
		return state.Certificate{}, err
	}
	if err := c.prepareDNS(); err != nil {
		return state.Certificate{}, err
	}
	kt, err := certcrypto.ToKeyType(keyType)
	if err != nil {
		return state.Certificate{}, err
	}

	if st.Order != nil && !orderMatches(st.Order, domains, string(kt), st.Server) {
		slog.Info("dropping order that does not match the requested certificate", "order", st.Order.Location)
		if err := c.discardOrder(ctx, st, save); err != nil {
			return state.Certificate{}, err
		}
	}

	if st.Order == nil {
		if err := c.createOrder(ctx, st, domains, kt, renew, save); err != nil {
			return state.Certificate{}, err
		}
	} else {
		slog.Info("resuming order", "order", st.Order.Location, "domains", strings.Join(domains, ","))
	}
	return c.completeOrder(ctx, st, save)
}

// DiscardOrder removes an order that is no longer needed and deletes any
// DNS-01 records it can still see. The certificate in st is left alone.
func (c *Client) DiscardOrder(ctx context.Context, st *state.State, save func(context.Context, *state.State) error) error {
	if st == nil || st.Order == nil {
		return nil
	}
	return c.discardOrder(ctx, st, save)
}

func (c *Client) createOrder(ctx context.Context, st *state.State, domains []string, kt certcrypto.KeyType, renew bool, save func(context.Context, *state.State) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	core, err := c.coreFor(st)
	if err != nil {
		return err
	}
	key, err := certificateKey(renew, st.Certificate, kt)
	if err != nil {
		return err
	}
	remote, err := core.Orders.New(ctx, domains, &api.OrderOptions{ReplacesCertID: replacesCertID(renew, st.Certificate)})
	if err != nil {
		return fmt.Errorf("create order: %w", err)
	}
	csr, err := buildCSR(domains, remote.Identifiers, key)
	if err != nil {
		return err
	}
	st.Order = &state.Order{
		Location:   remote.Location,
		Finalize:   remote.Finalize,
		Server:     st.Server,
		Domains:    append([]string(nil), domains...),
		KeyType:    string(kt),
		PrivateKey: certcrypto.PEMEncode(key),
		CSR:        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}),
	}
	slog.Info("order created", "order", remote.Location, "domains", strings.Join(domains, ","))
	if err := save(ctx, st); err != nil {
		return fmt.Errorf("save order: %w", err)
	}
	return nil
}

func (c *Client) completeOrder(ctx context.Context, st *state.State, save func(context.Context, *state.State) error) (state.Certificate, error) {
	core, err := c.coreFor(st)
	if err != nil {
		return state.Certificate{}, err
	}
	remote, err := core.Orders.Get(ctx, st.Order.Location)
	if err != nil {
		if orderGone(err) {
			slog.Warn("order is gone; a later attempt will create another", "order", st.Order.Location, "err", err)
			if clearErr := c.discardOrder(ctx, st, save); clearErr != nil {
				return state.Certificate{}, clearErr
			}
			return state.Certificate{}, err
		}
		return state.Certificate{}, fmt.Errorf("get order: %w", err)
	}
	remote.Location = st.Order.Location
	if remote.Finalize != "" {
		st.Order.Finalize = remote.Finalize
	}

	switch remote.Status {
	case acme.StatusPending:
		authzs, err := authorizations(ctx, core, remote.Authorizations)
		if err != nil {
			return state.Certificate{}, err
		}
		if err := c.solveAuthorizations(ctx, core, authzs); err != nil {
			if errors.Is(err, errAuthorizationFailed) {
				slog.Warn("authorization failed; dropping order", "order", st.Order.Location, "err", err)
				if clearErr := c.discardOrder(ctx, st, save); clearErr != nil {
					return state.Certificate{}, clearErr
				}
			}
			return state.Certificate{}, err
		}
		return c.finalizeAndDownload(ctx, core, st, save)
	case acme.StatusReady:
		return c.finalizeAndDownload(ctx, core, st, save)
	case acme.StatusProcessing, acme.StatusValid:
		return c.download(ctx, core, st, remote.Certificate, save)
	case acme.StatusInvalid, acme.StatusExpired, acme.StatusDeactivated:
		slog.Warn("dropping unusable order", "order", st.Order.Location, "status", remote.Status)
		if clearErr := c.discardOrder(ctx, st, save); clearErr != nil {
			return state.Certificate{}, clearErr
		}
		return state.Certificate{}, fmt.Errorf("%w: %s", errOrderInvalid, remote.Status)
	default:
		return state.Certificate{}, fmt.Errorf("unexpected order status %q", remote.Status)
	}
}

func (c *Client) finalizeAndDownload(ctx context.Context, core *api.Core, st *state.State, save func(context.Context, *state.State) error) (state.Certificate, error) {
	der, err := csrDER(st.Order.CSR)
	if err != nil {
		slog.Warn("dropping order with an unusable csr", "order", st.Order.Location, "err", err)
		if clearErr := c.discardOrder(ctx, st, save); clearErr != nil {
			return state.Certificate{}, clearErr
		}
		return state.Certificate{}, err
	}
	remote, err := core.Orders.UpdateForCSR(ctx, st.Order.Finalize, der)
	if err != nil {
		if orderGone(err) {
			slog.Warn("order disappeared during finalize", "order", st.Order.Location, "err", err)
			if clearErr := c.discardOrder(ctx, st, save); clearErr != nil {
				return state.Certificate{}, clearErr
			}
		}
		return state.Certificate{}, fmt.Errorf("finalize order: %w", err)
	}
	if remote.Status == acme.StatusInvalid || remote.Status == acme.StatusExpired || remote.Status == acme.StatusDeactivated {
		slog.Warn("order rejected during finalize", "order", st.Order.Location, "status", remote.Status)
		if clearErr := c.discardOrder(ctx, st, save); clearErr != nil {
			return state.Certificate{}, clearErr
		}
		return state.Certificate{}, fmt.Errorf("%w: %s: %v", errOrderInvalid, remote.Status, remote.Err())
	}
	return c.download(ctx, core, st, remote.Certificate, save)
}

func (c *Client) download(ctx context.Context, core *api.Core, st *state.State, certURL string, save func(context.Context, *state.State) error) (state.Certificate, error) {
	if certURL == "" {
		var err error
		certURL, err = c.waitCertificate(ctx, core, st.Order.Location)
		if err != nil {
			if errors.Is(err, errOrderInvalid) {
				if clearErr := c.discardOrder(ctx, st, save); clearErr != nil {
					return state.Certificate{}, clearErr
				}
			}
			return state.Certificate{}, err
		}
	}
	raw, err := core.Certificates.Get(ctx, certURL, true)
	if err != nil {
		return state.Certificate{}, fmt.Errorf("download certificate: %w", err)
	}
	id := ""
	if len(st.Order.Domains) > 0 {
		id = st.Order.Domains[0]
	}
	return state.Certificate{
		ID:                id,
		Domains:           append([]string(nil), st.Order.Domains...),
		KeyType:           st.Order.KeyType,
		Server:            st.Server,
		CertURL:           certURL,
		CertStableURL:     certURL,
		PrivateKey:        append([]byte(nil), st.Order.PrivateKey...),
		Certificate:       append([]byte(nil), raw.Cert...),
		IssuerCertificate: append([]byte(nil), raw.Issuer...),
		CSR:               append([]byte(nil), st.Order.CSR...),
	}, nil
}

func (c *Client) waitCertificate(ctx context.Context, core *api.Core, orderURL string) (string, error) {
	deadline := time.Now().Add(certificateWait)
	for {
		remote, err := core.Orders.Get(ctx, orderURL)
		if err != nil {
			return "", fmt.Errorf("poll order: %w", err)
		}
		switch remote.Status {
		case acme.StatusValid:
			if remote.Certificate == "" {
				return "", errors.New("valid order has no certificate url")
			}
			return remote.Certificate, nil
		case acme.StatusInvalid, acme.StatusExpired, acme.StatusDeactivated:
			return "", fmt.Errorf("%w: %s", errOrderInvalid, remote.Status)
		case acme.StatusProcessing, acme.StatusReady:
			if time.Now().After(deadline) {
				return "", errors.New("timed out waiting for the certificate")
			}
			if err := sleepCtx(ctx, 2*time.Second); err != nil {
				return "", err
			}
		default:
			return "", fmt.Errorf("unexpected order status %q", remote.Status)
		}
	}
}

func (c *Client) discardOrder(ctx context.Context, st *state.State, save func(context.Context, *state.State) error) error {
	if st.Order != nil {
		c.cleanupOrder(ctx, st)
		st.Order = nil
	}
	if save == nil {
		return errors.New("state save function is not configured")
	}
	if err := save(ctx, st); err != nil {
		return fmt.Errorf("clear order: %w", err)
	}
	return nil
}

func (c *Client) cleanupOrder(ctx context.Context, st *state.State) {
	if st.Order == nil || st.Order.Location == "" || st.Order.Server != st.Server {
		return
	}
	cleanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	core, err := c.coreFor(st)
	if err != nil {
		slog.Warn("dns cleanup skipped", "err", err)
		return
	}
	remote, err := core.Orders.Get(cleanCtx, st.Order.Location)
	if err != nil {
		slog.Warn("dns cleanup skipped", "order", st.Order.Location, "err", err)
		return
	}
	authzs, err := authorizations(cleanCtx, core, remote.Authorizations)
	if err != nil {
		slog.Warn("dns cleanup skipped", "order", st.Order.Location, "err", err)
		return
	}
	provider, _, _, err := c.dnsProvider()
	if err != nil {
		slog.Warn("dns cleanup skipped", "err", err)
		return
	}
	solver := dns01.NewChallenge(core, validateAuthorization, provider)
	cleanAuthorizations(authzs, solver)
}

func (c *Client) coreFor(st *state.State) (*api.Core, error) {
	account, err := c.user(st)
	if err != nil {
		return nil, err
	}
	cfg := lego.NewConfig(account)
	cfg.CADirURL = st.Server
	cfg.UserAgent = "kubelego"
	kid := ""
	if reg := account.GetRegistration(); reg != nil {
		kid = reg.Location
	}
	core, err := api.New(cfg.HTTPClient, cfg.UserAgent, st.Server, kid, account.GetPrivateKey())
	if err != nil {
		return nil, fmt.Errorf("acme directory: %w", err)
	}
	return core, nil
}

func authorizations(ctx context.Context, core *api.Core, urls []string) ([]acme.Authorization, error) {
	out := make([]acme.Authorization, 0, len(urls))
	for _, url := range urls {
		authz, err := core.Authorizations.Get(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("get authorization: %w", err)
		}
		out = append(out, authz)
	}
	return out, nil
}

func orderMatches(order *state.Order, domains []string, keyType, server string) bool {
	if order == nil || order.Location == "" || order.Finalize == "" || len(order.PrivateKey) == 0 || len(order.CSR) == 0 {
		return false
	}
	if order.Server != server || !strings.EqualFold(order.KeyType, keyType) {
		return false
	}
	return sameDomains(order.Domains, domains)
}

func sameDomains(have, want []string) bool {
	if len(have) != len(want) {
		return false
	}
	count := make(map[string]int, len(have))
	for _, domain := range have {
		count[strings.ToLower(domain)]++
	}
	for _, domain := range want {
		key := strings.ToLower(domain)
		count[key]--
		if count[key] < 0 {
			return false
		}
	}
	return true
}

func certificateKey(renew bool, existing *state.Certificate, kt certcrypto.KeyType) (crypto.Signer, error) {
	if renew && existing != nil && len(existing.PrivateKey) > 0 {
		key, err := certcrypto.ParsePEMPrivateKey(existing.PrivateKey)
		if err == nil {
			return key, nil
		}
		slog.Warn("reusing the certificate key failed; generating a new key", "err", err)
	}
	key, err := certcrypto.GeneratePrivateKey(kt)
	if err != nil {
		return nil, fmt.Errorf("generate certificate key: %w", err)
	}
	return key, nil
}

func replacesCertID(renew bool, cert *state.Certificate) string {
	if !renew || cert == nil || len(cert.Certificate) == 0 {
		return ""
	}
	parsed, err := certcrypto.ParsePEMBundle(cert.Certificate)
	if err != nil || len(parsed) == 0 {
		slog.Warn("renewal identifier skipped", "err", err)
		return ""
	}
	id, err := api.MakeARICertID(parsed[0])
	if err != nil {
		slog.Warn("renewal identifier skipped", "err", err)
		return ""
	}
	return id
}

func buildCSR(domains []string, identifiers []acme.Identifier, key crypto.Signer) ([]byte, error) {
	commonName := ""
	if len(domains) > 0 && len(domains[0]) <= 64 {
		commonName = domains[0]
	}
	san := make([]string, 0, len(identifiers)+1)
	if commonName != "" {
		san = append(san, commonName)
	}
	for _, id := range identifiers {
		if id.Value != commonName {
			san = append(san, id.Value)
		}
	}
	if len(san) == 0 {
		san = append(san, domains...)
	}
	csr, err := certcrypto.CreateCSR(key, certcrypto.CSROptions{Domain: commonName, SAN: san})
	if err != nil {
		return nil, fmt.Errorf("create csr: %w", err)
	}
	return csr, nil
}

func csrDER(raw []byte) ([]byte, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("order csr is not a certificate request")
	}
	if _, err := x509.ParseCertificateRequest(block.Bytes); err != nil {
		return nil, fmt.Errorf("parse csr: %w", err)
	}
	return block.Bytes, nil
}

func orderGone(err error) bool {
	var problem *acme.ProblemDetails
	if !errors.As(err, &problem) || problem == nil {
		return false
	}
	return problem.HTTPStatus == http.StatusNotFound || problem.HTTPStatus == http.StatusForbidden
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
