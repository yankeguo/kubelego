// Package cert turns ACME PEM material into a Kubernetes TLS secret payload.
package cert

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/certcrypto"
)

// Material is the data stored in a kubernetes.io/tls secret.
// TLSCrt is the leaf followed by intermediates, TLSKey is the private key,
// and CACrt is the issuer certificate (intermediate, plus the root when the
// CA returns it).
type Material struct {
	TLSCrt   []byte
	TLSKey   []byte
	CACrt    []byte
	NotAfter time.Time
}

// MaterialFromPEM builds a TLS secret payload.
// certPEM may be the leaf alone or a bundle. issuerPEM is the CA chain.
func MaterialFromPEM(certPEM, issuerPEM, keyPEM []byte) (Material, error) {
	if _, err := certcrypto.ParsePEMPrivateKey(keyPEM); err != nil {
		return Material{}, fmt.Errorf("parse private key: %w", err)
	}
	certs, err := certcrypto.ParsePEMBundle(certPEM)
	if err != nil {
		return Material{}, fmt.Errorf("parse certificate: %w", err)
	}
	if certs[0].IsCA {
		return Material{}, fmt.Errorf("certificate bundle starts with a CA certificate")
	}

	tlsCrt := certPEM
	if len(certs) == 1 && len(bytes.TrimSpace(issuerPEM)) > 0 {
		tlsCrt = joinPEM(certPEM, issuerPEM)
	}

	ca := issuerPEM
	if len(bytes.TrimSpace(ca)) == 0 && len(certs) > 1 {
		ca = encodeCertificates(certs[1:])
	}
	if len(bytes.TrimSpace(ca)) == 0 {
		return Material{}, fmt.Errorf("issuer certificate is missing")
	}

	return Material{
		TLSCrt:   normalizePEM(tlsCrt),
		TLSKey:   normalizePEM(keyPEM),
		CACrt:    normalizePEM(ca),
		NotAfter: certs[0].NotAfter,
	}, nil
}

// NeedsRenewal decides whether a stored certificate can be kept.
// The reason is "missing", "domains", "key-type", or "expiring".
// An empty reason means the certificate is still usable.
func NeedsRenewal(certPEM []byte, storedDomains []string, haveKeyType, wantKeyType string, wantDomains []string, renewBefore time.Duration, now time.Time) (string, error) {
	if len(bytes.TrimSpace(certPEM)) == 0 {
		return "missing", nil
	}
	if !sameDomains(storedDomains, wantDomains) {
		return "domains", nil
	}
	if haveKeyType != "" && !strings.EqualFold(haveKeyType, wantKeyType) {
		return "key-type", nil
	}

	certs, err := certcrypto.ParsePEMBundle(certPEM)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	if !certs[0].NotAfter.After(now.Add(renewBefore)) {
		return "expiring", nil
	}
	return "", nil
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

func normalizePEM(raw []byte) []byte {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil
	}
	out := make([]byte, len(raw)+1)
	copy(out, raw)
	out[len(raw)] = '\n'
	return out
}

func joinPEM(a, b []byte) []byte {
	return append(normalizePEM(a), normalizePEM(b)...)
}

func encodeCertificates(certs []*x509.Certificate) []byte {
	var buf bytes.Buffer
	for _, item := range certs {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: item.Raw})
	}
	return buf.Bytes()
}
