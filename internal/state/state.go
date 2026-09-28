// Package state is the ACME account and certificate document stored in a Secret.
package state

import (
	"encoding/json"
	"fmt"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
)

// Version is the on-disk schema version stored in state.json.
const Version = 1

// State is persisted as the state.json key of an opaque Secret.
type State struct {
	Version      int                   `json:"version"`
	Email        string                `json:"email,omitempty"`
	Server       string                `json:"server,omitempty"`
	AccountKey   []byte                `json:"accountKey,omitempty"`
	Registration *acme.ExtendedAccount `json:"registration,omitempty"`
	Certificate  *Certificate          `json:"certificate,omitempty"`
	Order        *Order                `json:"order,omitempty"`
}

// Certificate is a lego certificate resource with PEM fields included.
// lego's own Resource marks those fields json:"-", so they are stored here.
type Certificate struct {
	ID                string   `json:"id,omitempty"`
	Domains           []string `json:"domains,omitempty"`
	KeyType           string   `json:"keyType,omitempty"`
	Server            string   `json:"server,omitempty"`
	CertURL           string   `json:"certUrl,omitempty"`
	CertStableURL     string   `json:"certStableUrl,omitempty"`
	PrivateKey        []byte   `json:"privateKey,omitempty"`
	Certificate       []byte   `json:"certificate,omitempty"`
	IssuerCertificate []byte   `json:"issuerCertificate,omitempty"`
	CSR               []byte   `json:"csr,omitempty"`
}

// Order is an ACME order that has not produced a stored certificate yet.
// It is written before DNS-01 and before finalization, so a restart can
// continue the same order instead of opening another one.
type Order struct {
	Location   string   `json:"location"`
	Finalize   string   `json:"finalize,omitempty"`
	Server     string   `json:"server,omitempty"`
	Domains    []string `json:"domains,omitempty"`
	KeyType    string   `json:"keyType,omitempty"`
	PrivateKey []byte   `json:"privateKey,omitempty"`
	CSR        []byte   `json:"csr,omitempty"`
}

// FromResource copies an issued certificate into the persisted form.
func FromResource(res *certificate.Resource) Certificate {
	if res == nil {
		return Certificate{}
	}
	return Certificate{
		ID:                res.ID,
		Domains:           append([]string(nil), res.Domains...),
		KeyType:           string(res.KeyType),
		CertURL:           res.CertURL,
		CertStableURL:     res.CertStableURL,
		PrivateKey:        append([]byte(nil), res.PrivateKey...),
		Certificate:       append([]byte(nil), res.Certificate...),
		IssuerCertificate: append([]byte(nil), res.IssuerCertificate...),
		CSR:               append([]byte(nil), res.CSR...),
	}
}

// Resource converts the persisted certificate back into a lego resource.
func (c Certificate) Resource() certificate.Resource {
	return certificate.Resource{
		ID:                c.ID,
		Domains:           append([]string(nil), c.Domains...),
		KeyType:           certcrypto.KeyType(c.KeyType),
		CertURL:           c.CertURL,
		CertStableURL:     c.CertStableURL,
		PrivateKey:        append([]byte(nil), c.PrivateKey...),
		Certificate:       append([]byte(nil), c.Certificate...),
		IssuerCertificate: append([]byte(nil), c.IssuerCertificate...),
		CSR:               append([]byte(nil), c.CSR...),
	}
}

// Marshal encodes the state document.
func (s State) Marshal() ([]byte, error) {
	if s.Version == 0 {
		s.Version = Version
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode state: %w", err)
	}
	raw = append(raw, '\n')
	return raw, nil
}

// Parse decodes a state document.
func Parse(raw []byte) (*State, error) {
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("decode state: %w", err)
	}
	if st.Version != Version {
		return nil, fmt.Errorf("unsupported state version %d", st.Version)
	}
	return &st, nil
}
