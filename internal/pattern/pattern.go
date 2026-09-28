// Package pattern matches Kubernetes namespace names against shell globs.
// '*' matches any sequence of characters and '?' matches a single character.
package pattern

import (
	"fmt"
	"path"
	"strings"
)

// Split parses a comma-separated pattern list. Empty items are dropped.
func Split(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

// Validate reports patterns path.Match cannot compile.
func Validate(patterns []string) error {
	for _, pattern := range patterns {
		if _, err := path.Match(pattern, "x"); err != nil {
			return fmt.Errorf("namespace pattern %q: %w", pattern, err)
		}
	}
	return nil
}

// Matches reports whether name matches any pattern.
func Matches(name string, patterns []string) (bool, error) {
	for _, pattern := range patterns {
		ok, err := path.Match(pattern, name)
		if err != nil {
			return false, fmt.Errorf("namespace pattern %q: %w", pattern, err)
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}
