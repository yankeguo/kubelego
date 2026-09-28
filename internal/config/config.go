// Package config loads kubelego settings from the environment.
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/lego"
	"golang.org/x/net/idna"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/yankeguo/kubelego/internal/naming"
	"github.com/yankeguo/kubelego/internal/pattern"
)

// ServiceAccountNamespace is the in-cluster namespace file.
const ServiceAccountNamespace = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// SecretRef identifies a Secret. A bare name uses the pod namespace.
type SecretRef struct {
	Namespace string
	Name      string
}

func (r SecretRef) String() string {
	return r.Namespace + "/" + r.Name
}

// Config is the process configuration.
type Config struct {
	Email        string
	Domains      []string
	DNSProvider  string
	StateSecret  SecretRef
	CertSecret   SecretRef
	Namespaces   []string
	Server       string
	KeyType      string
	RenewBefore  time.Duration
	Interval     time.Duration
	Once         bool
	DNSResolvers []string
	DNSTimeout   time.Duration
	EABKID       string
	EABHMAC      string
}

// FromEnv reads configuration from the process environment.
func FromEnv() (Config, error) {
	return parse(os.Getenv, detectNamespace(os.Getenv))
}

func detectNamespace(getenv func(string) string) string {
	if ns := strings.TrimSpace(getenv("KUBELEGO_NAMESPACE")); ns != "" {
		return ns
	}
	raw, err := os.ReadFile(ServiceAccountNamespace)
	if err == nil {
		if ns := strings.TrimSpace(string(raw)); ns != "" {
			return ns
		}
	}
	return "default"
}

func parse(getenv func(string) string, namespace string) (Config, error) {
	var cfg Config

	cfg.Email = strings.TrimSpace(getenv("KUBELEGO_EMAIL"))
	if cfg.Email == "" || !strings.Contains(cfg.Email, "@") {
		return Config{}, fmt.Errorf("KUBELEGO_EMAIL must be an email address")
	}
	if !accepted(getenv("KUBELEGO_ACCEPT_TOS")) {
		return Config{}, fmt.Errorf("KUBELEGO_ACCEPT_TOS must be true to accept the ACME terms of service")
	}

	domains, err := splitDomains(getenv("KUBELEGO_DOMAINS"))
	if err != nil {
		return Config{}, err
	}
	cfg.Domains = domains

	cfg.DNSProvider = strings.ToLower(strings.TrimSpace(getenv("KUBELEGO_DNS_PROVIDER")))
	if cfg.DNSProvider == "" {
		return Config{}, fmt.Errorf("KUBELEGO_DNS_PROVIDER is required")
	}

	server, err := resolveServer(getenv("KUBELEGO_SERVER"))
	if err != nil {
		return Config{}, err
	}
	cfg.Server = server

	keyType := strings.TrimSpace(getenv("KUBELEGO_KEY_TYPE"))
	if keyType == "" {
		keyType = string(certcrypto.EC256)
	}
	parsedKeyType, err := certcrypto.ToKeyType(keyType)
	if err != nil {
		return Config{}, fmt.Errorf("KUBELEGO_KEY_TYPE: %w", err)
	}
	cfg.KeyType = string(parsedKeyType)

	cfg.RenewBefore, err = durationOr(getenv("KUBELEGO_RENEW_BEFORE"), 30*24*time.Hour)
	if err != nil {
		return Config{}, fmt.Errorf("KUBELEGO_RENEW_BEFORE: %w", err)
	}
	if cfg.RenewBefore <= 0 {
		return Config{}, fmt.Errorf("KUBELEGO_RENEW_BEFORE must be positive")
	}

	cfg.Once = accepted(getenv("KUBELEGO_ONCE"))
	intervalRaw := strings.TrimSpace(getenv("KUBELEGO_INTERVAL"))
	if intervalRaw == "" {
		cfg.Interval = time.Hour
	} else {
		cfg.Interval, err = parseDuration(intervalRaw)
		if err != nil {
			return Config{}, fmt.Errorf("KUBELEGO_INTERVAL: %w", err)
		}
	}
	if cfg.Interval <= 0 {
		cfg.Once = true
	}
	if !cfg.Once && cfg.Interval < time.Minute {
		return Config{}, fmt.Errorf("KUBELEGO_INTERVAL must be at least 1m")
	}

	cfg.Namespaces = pattern.Split(getenv("KUBELEGO_CERT_NAMESPACES"))
	if err := pattern.Validate(cfg.Namespaces); err != nil {
		return Config{}, fmt.Errorf("KUBELEGO_CERT_NAMESPACES: %w", err)
	}

	cfg.DNSResolvers, err = splitResolvers(getenv("KUBELEGO_DNS_RESOLVERS"))
	if err != nil {
		return Config{}, fmt.Errorf("KUBELEGO_DNS_RESOLVERS: %w", err)
	}
	if raw := strings.TrimSpace(getenv("KUBELEGO_DNS_TIMEOUT")); raw != "" {
		cfg.DNSTimeout, err = parseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("KUBELEGO_DNS_TIMEOUT: %w", err)
		}
		if cfg.DNSTimeout <= 0 {
			return Config{}, fmt.Errorf("KUBELEGO_DNS_TIMEOUT must be positive")
		}
	}

	cfg.EABKID = strings.TrimSpace(getenv("KUBELEGO_EAB_KID"))
	cfg.EABHMAC = strings.TrimSpace(getenv("KUBELEGO_EAB_HMAC"))
	if (cfg.EABKID == "") != (cfg.EABHMAC == "") {
		return Config{}, fmt.Errorf("KUBELEGO_EAB_KID and KUBELEGO_EAB_HMAC must be set together")
	}

	base := naming.FromDomain(cfg.Domains[0])
	cfg.CertSecret, err = parseSecretRef(getenv("KUBELEGO_CERT_SECRET"), namespace, base)
	if err != nil {
		return Config{}, fmt.Errorf("KUBELEGO_CERT_SECRET: %w", err)
	}
	cfg.StateSecret, err = parseSecretRef(getenv("KUBELEGO_STATE_SECRET"), namespace, base+"-state")
	if err != nil {
		return Config{}, fmt.Errorf("KUBELEGO_STATE_SECRET: %w", err)
	}
	return cfg, nil
}

func splitDomains(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("KUBELEGO_DOMAINS is required")
	}
	seen := map[string]struct{}{}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		domain, err := canonicalDomain(part)
		if err != nil {
			return nil, fmt.Errorf("KUBELEGO_DOMAINS: %w", err)
		}
		if domain == "" {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		out = append(out, domain)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("KUBELEGO_DOMAINS is required")
	}
	return out, nil
}

func canonicalDomain(domain string) (string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return "", nil
	}
	wildcard := strings.HasPrefix(domain, "*.")
	host := domain
	if wildcard {
		host = strings.TrimPrefix(domain, "*.")
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", fmt.Errorf("domain %q: %w", domain, err)
	}
	if ascii == "" || strings.ContainsAny(ascii, " *") {
		return "", fmt.Errorf("invalid domain %q", domain)
	}
	if wildcard {
		return "*." + ascii, nil
	}
	return ascii, nil
}

func resolveServer(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return lego.DirectoryURLLetsEncrypt, nil
	}
	if strings.Contains(raw, "://") {
		return raw, nil
	}
	url, err := lego.GetDirectoryURL(strings.ToLower(raw))
	if err != nil {
		return "", fmt.Errorf("KUBELEGO_SERVER: %w", err)
	}
	return url, nil
}

func parseSecretRef(raw, namespace, fallbackName string) (SecretRef, error) {
	ref := SecretRef{Namespace: namespace, Name: fallbackName}
	raw = strings.TrimSpace(raw)
	if raw != "" {
		ns, name, ok := strings.Cut(raw, "/")
		if !ok {
			ref.Name = raw
		} else {
			if ns == "" || name == "" || strings.Contains(name, "/") {
				return SecretRef{}, fmt.Errorf("invalid secret reference %q (want name or namespace/name)", raw)
			}
			ref.Namespace = ns
			ref.Name = name
		}
	}
	if ref.Namespace == "" || ref.Name == "" {
		return SecretRef{}, fmt.Errorf("namespace and name are required")
	}
	if msgs := validation.IsDNS1123Label(ref.Namespace); len(msgs) > 0 {
		return SecretRef{}, fmt.Errorf("namespace %q: %s", ref.Namespace, strings.Join(msgs, "; "))
	}
	if msgs := validation.IsDNS1123Subdomain(ref.Name); len(msgs) > 0 {
		return SecretRef{}, fmt.Errorf("name %q: %s", ref.Name, strings.Join(msgs, "; "))
	}
	return ref, nil
}

func splitResolvers(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		resolver, err := normalizeResolver(part)
		if err != nil {
			return nil, err
		}
		out = append(out, resolver)
	}
	return out, nil
}

func normalizeResolver(raw string) (string, error) {
	if _, _, err := net.SplitHostPort(raw); err == nil {
		return raw, nil
	}
	if strings.Contains(raw, ":") && !strings.HasPrefix(raw, "[") {
		raw = "[" + raw + "]"
	}
	return net.JoinHostPort(raw, "53"), nil
}

func durationOr(raw string, fallback time.Duration) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}
	return parseDuration(raw)
}

func parseDuration(raw string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(raw, "d"); ok && !strings.ContainsAny(days, "hms") {
		n, err := strconv.Atoi(days)
		if err != nil {
			return 0, fmt.Errorf("parse duration %q: %w", raw, err)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("parse duration %q: %w", raw, err)
	}
	return d, nil
}

func accepted(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "t", "true", "y", "yes":
		return true
	default:
		return false
	}
}
