package config

import (
	"strings"
	"testing"
	"time"
)

func TestParseDefaultsNameFromFirstDomain(t *testing.T) {
	cfg, err := parse(env(map[string]string{
		"KUBELEGO_EMAIL":        "ops@example.com",
		"KUBELEGO_ACCEPT_TOS":   "true",
		"KUBELEGO_DOMAINS":      "example.com, *.example.com",
		"KUBELEGO_DNS_PROVIDER": "Cloudflare",
	}), "kubelego")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DNSProvider != "cloudflare" {
		t.Fatalf("provider = %s", cfg.DNSProvider)
	}
	if strings.Join(cfg.Domains, ",") != "example.com,*.example.com" {
		t.Fatalf("domains = %#v", cfg.Domains)
	}
	if cfg.CertSecret.String() != "kubelego/example-com" {
		t.Fatalf("cert secret = %s", cfg.CertSecret)
	}
	if cfg.StateSecret.String() != "kubelego/example-com-state" {
		t.Fatalf("state secret = %s", cfg.StateSecret)
	}
	if cfg.Server == "" || cfg.KeyType != "EC256" || cfg.RenewBefore != 30*24*time.Hour || cfg.Interval != time.Hour {
		t.Fatalf("defaults = %+v", cfg)
	}
}

func TestParseWildcardNameAndExplicitSecrets(t *testing.T) {
	cfg, err := parse(env(map[string]string{
		"KUBELEGO_EMAIL":           "ops@example.com",
		"KUBELEGO_ACCEPT_TOS":      "yes",
		"KUBELEGO_DOMAINS":         "*.example.com,example.com",
		"KUBELEGO_DNS_PROVIDER":    "route53",
		"KUBELEGO_STATE_SECRET":    "cert-system/acme",
		"KUBELEGO_CERT_SECRET":     "ingress/wildcard.example.com",
		"KUBELEGO_CERT_NAMESPACES": "prod-*,staging,*",
		"KUBELEGO_SERVER":          "letsencrypt-staging",
		"KUBELEGO_RENEW_BEFORE":    "14d",
		"KUBELEGO_ONCE":            "true",
		"KUBELEGO_DNS_RESOLVERS":   "1.1.1.1,8.8.8.8:53",
	}), "kubelego")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CertSecret.String() != "ingress/wildcard.example.com" {
		t.Fatalf("cert secret = %s", cfg.CertSecret)
	}
	if cfg.StateSecret.String() != "cert-system/acme" {
		t.Fatalf("state secret = %s", cfg.StateSecret)
	}
	if cfg.Domains[0] != "*.example.com" {
		t.Fatalf("first domain = %s", cfg.Domains[0])
	}
	if cfg.Server != "https://acme-staging-v02.api.letsencrypt.org/directory" {
		t.Fatalf("server = %s", cfg.Server)
	}
	if cfg.RenewBefore != 14*24*time.Hour || !cfg.Once {
		t.Fatalf("schedule = %s once=%v", cfg.RenewBefore, cfg.Once)
	}
	if len(cfg.Namespaces) != 3 || cfg.DNSResolvers[0] != "1.1.1.1:53" || cfg.DNSResolvers[1] != "8.8.8.8:53" {
		t.Fatalf("namespaces=%v resolvers=%v", cfg.Namespaces, cfg.DNSResolvers)
	}
}

func TestParseRequiresTermsAndProvider(t *testing.T) {
	_, err := parse(env(map[string]string{
		"KUBELEGO_EMAIL":   "ops@example.com",
		"KUBELEGO_DOMAINS": "example.com",
	}), "default")
	if err == nil || !strings.Contains(err.Error(), "KUBELEGO_ACCEPT_TOS") {
		t.Fatalf("err = %v", err)
	}
}

func env(values map[string]string) func(string) string {
	return func(key string) string {
		return values[key]
	}
}
