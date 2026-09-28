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
	"strings"
	"testing"
	"time"

	legocme "github.com/go-acme/lego/v5/acme"

	"github.com/yankeguo/kubelego/internal/state"
)

func TestSyncSavesAccountBeforeObtain(t *testing.T) {
	fake := &fakeACME{}
	var stages []string
	svc := Service{
		ACME: fake,
		Save: func(_ context.Context, st *state.State) error {
			switch {
			case st.Registration == nil:
				stages = append(stages, "account-key")
			case st.Order != nil && st.Certificate == nil:
				stages = append(stages, "order")
			case st.Certificate != nil && st.Order == nil:
				stages = append(stages, "certificate")
			default:
				stages = append(stages, "account")
			}
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
	want := []string{"account-key", "account", "order", "certificate"}
	if strings.Join(stages, ",") != strings.Join(want, ",") {
		t.Fatalf("saves = %#v, want %#v", stages, want)
	}
	if fake.created != 1 || fake.renewed != 0 || fake.resumed != 0 {
		t.Fatalf("created=%d resumed=%d renew=%d", fake.created, fake.resumed, fake.renewed)
	}
	if fake.issueAfterSaves < 2 {
		t.Fatalf("issue happened after %d saves, want the account saved first", fake.issueAfterSaves)
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
	if fake.renewed != 1 || fake.created != 1 || fake.resumed != 0 {
		t.Fatalf("created=%d resumed=%d renew=%d", fake.created, fake.resumed, fake.renewed)
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
	if fake.created != 0 || fake.renewed != 0 || fake.resumed != 0 || saves != 0 {
		t.Fatalf("created=%d renew=%d resumed=%d saves=%d", fake.created, fake.renewed, fake.resumed, saves)
	}
}

func TestSyncKeepsOrderWhenIssueStops(t *testing.T) {
	leaf, issuer, key := mustChain(t, time.Now().Add(time.Hour))
	fake := &fakeACME{issueErr: errors.New("dns timeout"), leaf: leaf, issuer: issuer, key: key}
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
			Server:            svc.Server,
			Certificate:       leaf,
			IssuerCertificate: issuer,
			PrivateKey:        key,
		},
	}
	mat, err := svc.Sync(context.Background(), st)
	if err == nil || !strings.Contains(err.Error(), "dns timeout") {
		t.Fatalf("err = %v", err)
	}
	if len(mat.TLSCrt) == 0 || len(mat.TLSKey) == 0 {
		t.Fatal("stored certificate was not returned for publish")
	}
	if st.Order == nil || st.Order.Location == "" {
		t.Fatal("order was not checkpointed")
	}
	if string(st.Certificate.Certificate) != string(leaf) {
		t.Fatal("stored certificate was replaced before the new one was saved")
	}
	if fake.renewed != 1 || fake.created != 1 || fake.resumed != 0 {
		t.Fatalf("created=%d resumed=%d renew=%d", fake.created, fake.resumed, fake.renewed)
	}

	fake.issueErr = nil
	if _, err := svc.Sync(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if fake.created != 1 || fake.resumed != 1 || fake.renewed != 2 {
		t.Fatalf("created=%d resumed=%d renew=%d", fake.created, fake.resumed, fake.renewed)
	}
	if st.Order != nil {
		t.Fatal("finished order was kept")
	}
}

func TestSyncStoppedIssueDoesNotOpenAnotherOrder(t *testing.T) {
	fake := &fakeACME{cancelAfterCheckpoint: true}
	svc := Service{
		ACME:        fake,
		Save:        func(context.Context, *state.State) error { return nil },
		Email:       "ops@example.com",
		Server:      "https://acme.example/directory",
		Domains:     []string{"example.com"},
		KeyType:     "EC256",
		RenewBefore: time.Hour,
	}
	st := &state.State{
		Version:      state.Version,
		Email:        svc.Email,
		Server:       svc.Server,
		AccountKey:   []byte("already"),
		Registration: &legocme.ExtendedAccount{Location: "https://acme.example/acct/1"},
	}
	_, err := svc.Sync(context.Background(), st)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if st.Order == nil || fake.created != 1 {
		t.Fatalf("order=%v created=%d", st.Order, fake.created)
	}

	fake.cancelAfterCheckpoint = false
	if _, err := svc.Sync(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if fake.created != 1 || fake.resumed != 1 {
		t.Fatalf("created=%d resumed=%d", fake.created, fake.resumed)
	}
}

type fakeACME struct {
	created               int
	resumed               int
	renewed               int
	issueAfterSaves       int
	saves                 int
	issueErr              error
	cancelAfterCheckpoint bool
	leaf                  []byte
	issuer                []byte
	key                   []byte
}

func (f *fakeACME) EnsureAccount(ctx context.Context, st *state.State, email, server, _, _ string, save func(context.Context, *state.State) error) error {
	if st.Registration != nil && len(st.AccountKey) > 0 && st.Email == email && st.Server == server {
		return nil
	}
	if len(st.AccountKey) == 0 {
		st.AccountKey = []byte("generated")
		st.Registration = nil
		st.Email = email
		st.Server = server
		if err := save(ctx, st); err != nil {
			return err
		}
	}
	st.Email = email
	st.Server = server
	st.Registration = &legocme.ExtendedAccount{Location: "https://acme.example/acct/1"}
	return save(ctx, st)
}

func (f *fakeACME) Issue(ctx context.Context, st *state.State, domains []string, keyType string, renew bool, save func(context.Context, *state.State) error) (state.Certificate, error) {
	if err := ctx.Err(); err != nil {
		return state.Certificate{}, err
	}
	if renew {
		f.renewed++
	}
	f.issueAfterSaves = f.saves
	if st.Order == nil {
		f.created++
		st.Order = &state.Order{
			Location:   "https://acme.example/order/1",
			Finalize:   "https://acme.example/order/1/finalize",
			Server:     st.Server,
			Domains:    append([]string(nil), domains...),
			KeyType:    keyType,
			PrivateKey: []byte("pending-key"),
			CSR:        []byte("csr"),
		}
		if err := save(ctx, st); err != nil {
			return state.Certificate{}, err
		}
	} else {
		f.resumed++
	}
	if f.cancelAfterCheckpoint {
		return state.Certificate{}, context.Canceled
	}
	if f.issueErr != nil {
		return state.Certificate{}, f.issueErr
	}
	return f.issued(), nil
}

func (f *fakeACME) DiscardOrder(ctx context.Context, st *state.State, save func(context.Context, *state.State) error) error {
	st.Order = nil
	if save == nil {
		return nil
	}
	return save(ctx, st)
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
