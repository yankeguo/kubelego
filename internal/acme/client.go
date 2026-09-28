// Package acme issues certificates with the lego library using DNS-01.
package acme

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	legocme "github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/providers/dns"
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
// changed is true when st must be persisted before a certificate is requested.
func (c *Client) EnsureAccount(ctx context.Context, st *state.State, email, server, kid, hmac string) (bool, error) {
	changed := false
	if st.Version == 0 {
		st.Version = state.Version
		changed = true
	}
	if len(st.AccountKey) == 0 {
		key, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
		if err != nil {
			return false, fmt.Errorf("generate account key: %w", err)
		}
		st.AccountKey = certcrypto.PEMEncode(key)
		st.Registration = nil
		st.Certificate = nil
		changed = true
	}

	if st.Server != "" && st.Server != server {
		st.Registration = nil
		st.Certificate = nil
		changed = true
	}
	st.Server = server

	emailChanged := st.Email != "" && st.Email != email
	if st.Email != email {
		st.Email = email
		changed = true
	}

	account, err := c.user(st)
	if err != nil {
		return false, err
	}
	client, err := newClient(account, server)
	if err != nil {
		return false, err
	}

	if st.Registration == nil {
		reg, err := register(ctx, client, server, email, kid, hmac)
		if err != nil {
			return false, err
		}
		st.Registration = reg
		return true, nil
	}

	if emailChanged {
		reg, err := client.Registration.UpdateRegistration(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return false, fmt.Errorf("update account contact: %w", err)
		}
		st.Registration = reg
		changed = true
	}
	return changed, nil
}

// Obtain requests a new certificate for domains.
func (c *Client) Obtain(ctx context.Context, st *state.State, domains []string, keyType string) (state.Certificate, error) {
	client, kt, err := c.ready(st, keyType)
	if err != nil {
		return state.Certificate{}, err
	}
	res, err := client.Certificate.Obtain(ctx, certificate.ObtainRequest{
		Domains:          domains,
		Bundle:           true,
		EnableCommonName: true,
		KeyType:          kt,
	})
	if err != nil {
		return state.Certificate{}, fmt.Errorf("obtain certificate: %w", err)
	}
	return state.FromResource(res), nil
}

// Renew renews the certificate already stored in st, reusing its private key.
func (c *Client) Renew(ctx context.Context, st *state.State, keyType string) (state.Certificate, error) {
	if st.Certificate == nil {
		return state.Certificate{}, fmt.Errorf("renew certificate: no certificate in state")
	}
	client, kt, err := c.ready(st, keyType)
	if err != nil {
		return state.Certificate{}, err
	}
	res, err := client.Certificate.Renew(ctx, st.Certificate.Resource(), &certificate.RenewOptions{
		Bundle:           true,
		EnableCommonName: true,
		UseARICertID:     true,
		KeyType:          kt,
	})
	if err != nil {
		return state.Certificate{}, fmt.Errorf("renew certificate: %w", err)
	}
	return state.FromResource(res), nil
}

func (c *Client) ready(st *state.State, keyType string) (*lego.Client, certcrypto.KeyType, error) {
	if err := c.prepareDNS(); err != nil {
		return nil, "", err
	}
	account, err := c.user(st)
	if err != nil {
		return nil, "", err
	}
	client, err := newClient(account, st.Server)
	if err != nil {
		return nil, "", err
	}
	provider, err := c.challengeProvider()
	if err != nil {
		return nil, "", err
	}
	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return nil, "", fmt.Errorf("configure dns-01: %w", err)
	}
	kt, err := certcrypto.ToKeyType(keyType)
	if err != nil {
		return nil, "", err
	}
	return client, kt, nil
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

func (c *Client) challengeProvider() (challenge.Provider, error) {
	// Same factory as the lego CLI, including every built-in provider and alias.
	// Provider credentials stay in that provider's own environment variables.
	provider, err := dns.NewDNSChallengeProviderByName(c.Provider)
	if err != nil {
		return nil, fmt.Errorf("dns provider %q: %w", c.Provider, err)
	}
	if c.Timeout <= 0 {
		return provider, nil
	}
	interval := 2 * time.Second
	if c.Timeout < interval {
		interval = c.Timeout
	}
	return timeoutProvider{Provider: provider, timeout: c.Timeout, interval: interval}, nil
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
