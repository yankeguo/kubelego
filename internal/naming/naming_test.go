package naming

import "testing"

func TestFromDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{domain: "example.com", want: "example.com"},
		{domain: "*.example.com", want: "wildcard.example.com"},
		{domain: "EXAMPLE.COM", want: "example.com"},
		{domain: "_foo.example.com", want: "foo.example.com"},
		{domain: "", want: "certificate"},
		{domain: "*.*.example.com", want: "wildcard.wildcard.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			if got := FromDomain(tt.domain); got != tt.want {
				t.Fatalf("FromDomain(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}
