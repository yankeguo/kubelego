// Package issue decides when to register, obtain, or renew, and persists state
// before each step that can be interrupted.
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
	// EnsureAccount saves the account key before registration and saves the
	// registration before returning.
	EnsureAccount(ctx context.Context, st *state.State, email, server, kid, hmac string, save func(context.Context, *state.State) error) error
	// Issue creates or resumes st.Order. The order is saved before the DNS-01
	// challenge. A failure leaves a resumable order unless the CA rejected it.
	Issue(ctx context.Context, st *state.State, domains []string, keyType string, renew bool, save func(context.Context, *state.State) error) (state.Certificate, error)
	// DiscardOrder clears st.Order after a best-effort DNS cleanup.
	DiscardOrder(ctx context.Context, st *state.State, save func(context.Context, *state.State) error) error
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

// Sync registers the account, issues or resumes a certificate, and returns the
// TLS secret payload. Interrupted work stays in st so the next Sync finishes it.
func (s Service) Sync(ctx context.Context, st *state.State) (cert.Material, error) {
	if st == nil {
		st = &state.State{Version: state.Version}
	}
	if err := s.ACME.EnsureAccount(ctx, st, s.Email, s.Server, s.EABKID, s.EABHMAC, s.save); err != nil {
		return cert.Material{}, err
	}

	reason, err := s.reason(st)
	if err != nil {
		return cert.Material{}, err
	}
	if reason == "" {
		if st.Order != nil {
			slog.Info("clearing order because the stored certificate is still valid")
			if err := s.ACME.DiscardOrder(ctx, st, s.save); err != nil {
				return cert.Material{}, err
			}
		}
		return cert.MaterialFromPEM(st.Certificate.Certificate, st.Certificate.IssuerCertificate, st.Certificate.PrivateKey)
	}

	slog.Info("requesting certificate", "reason", reason, "domains", strings.Join(s.Domains, ","))
	issued, err := s.ACME.Issue(ctx, st, s.Domains, s.KeyType, reason == "expiring", s.save)
	if err != nil {
		if mat, ok := storedMaterial(st); ok {
			slog.Warn("certificate request failed; keeping the stored certificate", "err", err)
			return mat, err
		}
		return cert.Material{}, err
	}
	issued.Server = s.Server
	if len(issued.Domains) == 0 {
		issued.Domains = append([]string(nil), s.Domains...)
	}
	st.Certificate = &issued
	st.Order = nil
	if err := s.save(ctx, st); err != nil {
		slog.Error("certificate issued but not saved; the stored order will be resumed", "err", err)
		return cert.Material{}, fmt.Errorf("save certificate: %w", err)
	}
	return cert.MaterialFromPEM(issued.Certificate, issued.IssuerCertificate, issued.PrivateKey)
}

func storedMaterial(st *state.State) (cert.Material, bool) {
	if st == nil || st.Certificate == nil {
		return cert.Material{}, false
	}
	mat, err := cert.MaterialFromPEM(st.Certificate.Certificate, st.Certificate.IssuerCertificate, st.Certificate.PrivateKey)
	if err != nil {
		return cert.Material{}, false
	}
	return mat, true
}

func (s Service) reason(st *state.State) (string, error) {
	var (
		certPEM       []byte
		storedDomains []string
		haveKeyType   string
		certServer    string
	)
	if st.Certificate != nil {
		certPEM = st.Certificate.Certificate
		storedDomains = st.Certificate.Domains
		haveKeyType = st.Certificate.KeyType
		certServer = st.Certificate.Server
	}
	reason, err := cert.NeedsRenewal(certPEM, storedDomains, haveKeyType, s.KeyType, s.Domains, s.RenewBefore, s.now())
	if err != nil || reason != "" {
		return reason, err
	}
	if certServer != "" && certServer != s.Server {
		return "server", nil
	}
	return "", nil
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
