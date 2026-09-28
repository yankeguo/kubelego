package issue

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	legocme "github.com/go-acme/lego/v5/acme"

	"github.com/yankeguo/kubelego/internal/state"
)

func TestSyncSavesAccountBeforeObtain(t *testing.T) {
	fake := &fakeACME{}
	var calls []string
	svc := Service{
		ACME: fake,
		Save: func(context.Context, *state.State) error {
			calls = append(calls, "save")
			fake.saves++
			return nil
		},
		Email:       "ops@example.com",
		Server:      "https://acme.example/directory",
		Domains:     []string{"example.com"},
		KeyType:     "EC256",
		RenewBefore: time.Hour,
	}

	if _, err := svc.Sync(context.Background(), &state.State{Version: state.Version}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0] != "save" || calls[1] != "save" {
		t.Fatalf("saves = %#v, want account save then certificate save", calls)
	}
	if fake.obtained != 1 || fake.renewed != 0 {
		t.Fatalf("obtain=%d renew=%d", fake.obtained, fake.renewed)
	}
	if fake.obtainAfterSaves != 1 {
		t.Fatalf("obtain happened after %d saves, want 1", fake.obtainAfterSaves)
	}
}

func TestSyncRenewsExpiringCertificate(t *testing.T) {
	leaf, issuer, key := mustChain(t, time.Now().Add(24*time.Hour))
	fake := &fakeACME{leaf: leaf, issuer: issuer, key: key}
	svc := Service{
		ACME:        fake,
		Save:        func(context.Context, *state.State) error { return nil },
		Email:       "ops@example.com",
		Server:      "https://acme.example/directory",
		Domains:     []string{"example.com"},
		KeyType:     "EC256",
		RenewBefore: 7 * 24 * time.Hour,
		Now:         func() time.Time { return time.Now() },
	}
	st := &state.State{
		Version:      state.Version,
		Email:        "ops@example.com",
		Server:       svc.Server,
		AccountKey:   []byte("already"),
		Registration: &legocme.ExtendedAccount{Location: "https://acme.example/acct/1"},
		Certificate: &state.Certificate{
			Domains:           []string{"example.com"},
			KeyType:           "EC256",
			Certificate:       leaf,
			IssuerCertificate: issuer,
			PrivateKey:        key,
		},
	}
	if _, err := svc.Sync(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if fake.renewed != 1 || fake.obtained != 0 {
		t.Fatalf("obtain=%d renew=%d", fake.obtained, fake.renewed)
	}
}

func TestSyncKeepsFreshCertificate(t *testing.T) {
	leaf, issuer, key := mustChain(t, time.Now().Add(60*24*time.Hour))
	fake := &fakeACME{}
	saves := 0
	svc := Service{
		ACME: fake,
		Save: func(context.Context, *state.State) error {
			saves++
			return nil
		},
		Email:       "ops@example.com",
		Server:      "https://acme.example/directory",
		Domains:     []string{"example.com"},
		KeyType:     "EC256",
		RenewBefore: 30 * 24 * time.Hour,
	}
	st := &state.State{
		Version:      state.Version,
		Email:        svc.Email,
		Server:       svc.Server,
		AccountKey:   []byte("already"),
		Registration: &legocme.ExtendedAccount{Location: "https://acme.example/acct/1"},
		Certificate: &state.Certificate{
			Domains:           []string{"example.com"},
			KeyType:           "EC256",
			Certificate:       leaf,
			IssuerCertificate: issuer,
			PrivateKey:        key,
		},
	}
	if _, err := svc.Sync(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if fake.obtained != 0 || fake.renewed != 0 || saves != 0 {
		t.Fatalf("obtain=%d renew=%d saves=%d", fake.obtained, fake.renewed, saves)
	}
}

func TestSyncFallsBackToObtainWhenRenewFails(t *testing.T) {
	leaf, issuer, key := mustChain(t, time.Now().Add(time.Hour))
	fake := &fakeACME{renewErr: errors.New("order gone"), leaf: leaf, issuer: issuer, key: key}
	svc := Service{
		ACME:        fake,
		Save:        func(context.Context, *state.State) error { return nil },
		Email:       "ops@example.com",
		Server:      "https://acme.example/directory",
		Domains:     []string{"example.com"},
		KeyType:     "EC256",
		RenewBefore: 48 * time.Hour,
	}
	st := &state.State{
		Version:      state.Version,
		Email:        svc.Email,
		Server:       svc.Server,
		AccountKey:   []byte("already"),
		Registration: &legocme.ExtendedAccount{Location: "https://acme.example/acct/1"},
		Certificate: &state.Certificate{
			Domains:           []string{"example.com"},
			KeyType:           "EC256",
			Certificate:       leaf,
			IssuerCertificate: issuer,
			PrivateKey:        key,
		},
	}
	if _, err := svc.Sync(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if fake.renewed != 1 || fake.obtained != 1 {
		t.Fatalf("obtain=%d renew=%d", fake.obtained, fake.renewed)
	}
}

type fakeACME struct {
	obtained         int
	renewed          int
	obtainAfterSaves int
	saves            int
	renewErr         error
	leaf             []byte
	issuer           []byte
	key              []byte
}

func (f *fakeACME) EnsureAccount(_ context.Context, st *state.State, email, server, _, _ string) (bool, error) {
	if st.Registration != nil && len(st.AccountKey) > 0 && st.Email == email && st.Server == server {
		return false, nil
	}
	st.Email = email
	st.Server = server
	if len(st.AccountKey) == 0 {
		st.AccountKey = []byte("generated")
	}
	st.Registration = &legocme.ExtendedAccount{Location: "https://acme.example/acct/1"}
	return true, nil
}

func (f *fakeACME) Obtain(context.Context, *state.State, []string, string) (state.Certificate, error) {
	f.obtained++
	f.obtainAfterSaves = f.saves
	return f.issued(), nil
}

func (f *fakeACME) Renew(context.Context, *state.State, string) (state.Certificate, error) {
	f.renewed++
	if f.renewErr != nil {
		return state.Certificate{}, f.renewErr
	}
	return f.issued(), nil
}

func (f *fakeACME) issued() state.Certificate {
	leaf, issuer, key := f.leaf, f.issuer, f.key
	if len(leaf) == 0 {
		leaf, issuer, key = mustChain(nopT{}, time.Now().Add(90*24*time.Hour))
	}
	return state.Certificate{
		Domains:           []string{"example.com"},
		KeyType:           "EC256",
		Certificate:       leaf,
		IssuerCertificate: issuer,
		PrivateKey:        key,
	}
}

type nopT struct{}

func (nopT) Helper()                           {}
func (nopT) Fatal(args ...any)                 { panic(args) }
func (nopT) Fatalf(format string, args ...any) { panic(args) }

func mustChain(t testingTB, notAfter time.Time) (leafPEM, issuerPEM, keyPEM []byte) {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Hour)
	issuerTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTpl, issuerTpl, issuerKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    now,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, issuer, leafKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

type testingTB interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}
