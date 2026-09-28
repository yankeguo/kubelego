// Package issue decides when to register, obtain, or renew, and persists state
// before a certificate request so a failed challenge does not lose the account.
package issue

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/yankeguo/kubelego/internal/cert"
	"github.com/yankeguo/kubelego/internal/state"
)

// ACME is the subset of the lego client used by Sync.
type ACME interface {
	EnsureAccount(ctx context.Context, st *state.State, email, server, kid, hmac string) (changed bool, err error)
	Obtain(ctx context.Context, st *state.State, domains []string, keyType string) (state.Certificate, error)
	Renew(ctx context.Context, st *state.State, keyType string) (state.Certificate, error)
}

// Service reconciles one certificate.
type Service struct {
	ACME        ACME
	Save        func(context.Context, *state.State) error
	Now         func() time.Time
	Email       string
	Server      string
	EABKID      string
	EABHMAC     string
	Domains     []string
	KeyType     string
	RenewBefore time.Duration
}

// Sync loads nothing itself. The caller passes the current state and receives
// the TLS secret payload. Account changes are saved before any certificate request.
func (s Service) Sync(ctx context.Context, st *state.State) (cert.Material, error) {
	if st == nil {
		st = &state.State{Version: state.Version}
	}
	changed, err := s.ACME.EnsureAccount(ctx, st, s.Email, s.Server, s.EABKID, s.EABHMAC)
	if err != nil {
		return cert.Material{}, err
	}
	if changed {
		if err := s.save(ctx, st); err != nil {
			return cert.Material{}, fmt.Errorf("save account: %w", err)
		}
	}

	var (
		certPEM       []byte
		storedDomains []string
		haveKeyType   string
	)
	if st.Certificate != nil {
		certPEM = st.Certificate.Certificate
		storedDomains = st.Certificate.Domains
		haveKeyType = st.Certificate.KeyType
	}

	reason, err := cert.NeedsRenewal(certPEM, storedDomains, haveKeyType, s.KeyType, s.Domains, s.RenewBefore, s.now())
	if err != nil {
		return cert.Material{}, err
	}
	if reason == "" {
		return cert.MaterialFromPEM(st.Certificate.Certificate, st.Certificate.IssuerCertificate, st.Certificate.PrivateKey)
	}

	slog.Info("requesting certificate", "reason", reason, "domains", strings.Join(s.Domains, ","))
	issued, err := s.request(ctx, st, reason)
	if err != nil {
		return cert.Material{}, err
	}
	st.Certificate = &issued
	if err := s.save(ctx, st); err != nil {
		slog.Error("certificate issued but not saved; a later attempt may request another one", "err", err)
		return cert.Material{}, fmt.Errorf("save certificate: %w", err)
	}
	return cert.MaterialFromPEM(issued.Certificate, issued.IssuerCertificate, issued.PrivateKey)
}

func (s Service) request(ctx context.Context, st *state.State, reason string) (state.Certificate, error) {
	if reason != "expiring" {
		return s.ACME.Obtain(ctx, st, s.Domains, s.KeyType)
	}
	issued, err := s.ACME.Renew(ctx, st, s.KeyType)
	if err == nil {
		return issued, nil
	}
	slog.Warn("renew failed, obtaining a new certificate", "err", err)
	return s.ACME.Obtain(ctx, st, s.Domains, s.KeyType)
}

func (s Service) save(ctx context.Context, st *state.State) error {
	if s.Save == nil {
		return fmt.Errorf("state save function is not configured")
	}
	return s.Save(ctx, st)
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}
