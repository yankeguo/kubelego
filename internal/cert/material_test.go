package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestMaterialFromPEMBundlesLeafAndIssuer(t *testing.T) {
	leafPEM, issuerPEM, keyPEM, notAfter := testChain(t, time.Now().Add(90*24*time.Hour))

	got, err := MaterialFromPEM(leafPEM, issuerPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := parseAll(got.TLSCrt)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 {
		t.Fatalf("tls.crt has %d certificates, want leaf and issuer", len(certs))
	}
	if certs[0].Subject.CommonName != "example.com" {
		t.Fatalf("leaf CN = %s", certs[0].Subject.CommonName)
	}
	if certs[1].Subject.CommonName != "Test CA" {
		t.Fatalf("issuer CN = %s", certs[1].Subject.CommonName)
	}
	ca, err := parseAll(got.CACrt)
	if err != nil {
		t.Fatal(err)
	}
	if len(ca) != 1 || ca[0].Subject.CommonName != "Test CA" {
		t.Fatalf("ca.crt = %+v", ca)
	}
	if _, err := parseKey(got.TLSKey); err != nil {
		t.Fatal(err)
	}
	if !got.NotAfter.Equal(notAfter) {
		t.Fatalf("NotAfter = %s, want %s", got.NotAfter, notAfter)
	}
}

func TestMaterialFromPEMUsesBundleWhenIssuerMissing(t *testing.T) {
	leafPEM, issuerPEM, keyPEM, _ := testChain(t, time.Now().Add(time.Hour))
	bundle := append(append([]byte{}, leafPEM...), issuerPEM...)

	got, err := MaterialFromPEM(bundle, nil, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := parseAll(got.CACrt)
	if err != nil {
		t.Fatal(err)
	}
	if len(ca) != 1 || ca[0].Subject.CommonName != "Test CA" {
		t.Fatalf("ca.crt subjects = %s", ca[0].Subject.CommonName)
	}
}

func TestNeedsRenewal(t *testing.T) {
	now := time.Now()
	leafPEM, _, _, notAfter := testChain(t, now.Add(10*24*time.Hour))
	domains := []string{"example.com", "*.example.com"}

	reason, err := NeedsRenewal(nil, nil, "", "EC256", domains, 30*24*time.Hour, now)
	if err != nil || reason != "missing" {
		t.Fatalf("missing: reason=%q err=%v", reason, err)
	}

	reason, err = NeedsRenewal(leafPEM, []string{"example.com"}, "EC256", "EC256", domains, time.Hour, now)
	if err != nil || reason != "domains" {
		t.Fatalf("domains: reason=%q err=%v", reason, err)
	}

	reason, err = NeedsRenewal(leafPEM, domains, "RSA2048", "EC256", domains, time.Hour, now)
	if err != nil || reason != "key-type" {
		t.Fatalf("key-type: reason=%q err=%v", reason, err)
	}

	reason, err = NeedsRenewal(leafPEM, domains, "EC256", "EC256", domains, 30*24*time.Hour, now)
	if err != nil || reason != "expiring" {
		t.Fatalf("expiring: reason=%q err=%v notAfter=%s", reason, err, notAfter)
	}

	reason, err = NeedsRenewal(leafPEM, []string{"*.example.com", "example.com"}, "ec256", "EC256", domains, time.Hour, now)
	if err != nil || reason != "" {
		t.Fatalf("fresh: reason=%q err=%v", reason, err)
	}
}

func testChain(t *testing.T, notAfter time.Time) (leafPEM, issuerPEM, keyPEM []byte, leafNotAfter time.Time) {
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
		DNSNames:     []string{"example.com", "*.example.com"},
		NotBefore:    now,
		NotAfter:     notAfter.UTC().Truncate(time.Second),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, issuer, leafKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		leaf.NotAfter
}

func parseAll(raw []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		item, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}

func parseKey(raw []byte) (any, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errNoPEM
	}
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

var errNoPEM = errString("no pem")

type errString string

func (e errString) Error() string { return string(e) }
