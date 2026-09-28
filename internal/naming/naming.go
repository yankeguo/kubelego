// Package naming derives DNS-1123 names from certificate domains.
package naming

import (
	"strings"
	"unicode"
)

// FromDomain builds a Kubernetes resource name from a domain.
// The first domain of a certificate is the name source: a leading wildcard
// becomes the literal label "wildcard", and every other unsupported
// character becomes a hyphen.
func FromDomain(domain string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(domain)) {
		switch {
		case r == '*':
			writeSegment(&b, &prevDash, "wildcard")
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		case r == '.':
			if b.Len() == 0 || prevDash {
				continue
			}
			b.WriteByte('.')
			prevDash = false
		case r == '-' || unicode.IsSpace(r):
			if b.Len() == 0 || prevDash {
				continue
			}
			b.WriteByte('-')
			prevDash = true
		default:
			if b.Len() == 0 || prevDash {
				continue
			}
			b.WriteByte('-')
			prevDash = true
		}
	}

	out := strings.Trim(b.String(), "-.")
	for strings.Contains(out, "..") {
		out = strings.ReplaceAll(out, "..", ".")
	}
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	const max = 240
	if len(out) > max {
		out = strings.Trim(out[:max], "-.")
	}
	if out == "" {
		return "certificate"
	}
	return out
}

func writeSegment(b *strings.Builder, prevDash *bool, segment string) {
	if b.Len() > 0 && !*prevDash {
		last := b.String()[b.Len()-1]
		if last != '.' {
			b.WriteByte('-')
		}
	}
	b.WriteString(segment)
	*prevDash = false
}
