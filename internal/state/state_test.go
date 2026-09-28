package state

import (
	"testing"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
)

func TestRoundTrip(t *testing.T) {
	original := State{
		Version:    Version,
		Email:      "ops@example.com",
		Server:     "https://acme-v02.api.letsencrypt.org/directory",
		AccountKey: []byte("-----BEGIN PRIVATE KEY-----\nYQ==\n-----END PRIVATE KEY-----\n"),
		Registration: &acme.ExtendedAccount{
			Account:  acme.Account{Status: "valid"},
			Location: "https://acme.example/acme/acct/1",
		},
		Certificate: &Certificate{
			ID:          "example.com",
			Domains:     []string{"example.com", "*.example.com"},
			KeyType:     string(certcrypto.EC256),
			Server:      "https://acme-v02.api.letsencrypt.org/directory",
			PrivateKey:  []byte("key"),
			Certificate: []byte("cert"),
		},
		Order: &Order{
			Location: "https://acme.example/order/1",
			Domains:  []string{"example.com"},
			KeyType:  string(certcrypto.EC256),
		},
	}

	raw, err := original.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Email != original.Email || got.Registration.Location != original.Registration.Location {
		t.Fatalf("account did not round-trip: %+v", got)
	}
	if string(got.Certificate.Certificate) != "cert" || got.Certificate.KeyType != string(certcrypto.EC256) || got.Certificate.Server == "" {
		t.Fatalf("certificate did not round-trip: %+v", got.Certificate)
	}
	if got.Order == nil || got.Order.Location != original.Order.Location {
		t.Fatalf("order did not round-trip: %+v", got.Order)
	}

	res := got.Certificate.Resource()
	if res.KeyType != certcrypto.EC256 || string(res.PrivateKey) != "key" {
		t.Fatalf("resource = %+v", res)
	}
}

func TestParseRejectsUnknownVersion(t *testing.T) {
	if _, err := Parse([]byte(`{"version":2}`)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestFromResourceCopiesPEM(t *testing.T) {
	res := &certificate.Resource{
		ID:          "example.com",
		Domains:     []string{"example.com"},
		KeyType:     certcrypto.EC256,
		PrivateKey:  []byte("key"),
		Certificate: []byte("cert"),
	}
	got := FromResource(res)
	got.PrivateKey[0] = 'K'
	if string(res.PrivateKey) != "key" {
		t.Fatal("private key was not copied")
	}
}
