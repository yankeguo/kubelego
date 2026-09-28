package acme

import (
	"strings"
	"testing"

	"github.com/go-acme/lego/v5/providers/dns"
)

func TestProviderFactoryIncludesLegoProviders(t *testing.T) {
	// These names come from lego's generated factory, including aliases.
	// A missing credential is fine; "unrecognized DNS provider" means the
	// provider was dropped from the binary.
	names := []string{"cloudflare", "route53", "alidns", "rfc2136", "acme-dns", "exec", "manual"}
	for _, name := range names {
		_, err := dns.NewDNSChallengeProviderByName(name)
		if err != nil && strings.Contains(err.Error(), "unrecognized DNS provider") {
			t.Errorf("%s was not recognized: %v", name, err)
		}
	}

	_, err := dns.NewDNSChallengeProviderByName("not-a-provider")
	if err == nil || !strings.Contains(err.Error(), "unrecognized DNS provider") {
		t.Fatalf("unknown provider error = %v", err)
	}
}
