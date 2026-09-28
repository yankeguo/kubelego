package acme

import (
	"time"

	"github.com/go-acme/lego/v5/challenge"
)

// timeoutProvider overrides the DNS-01 propagation timeout reported to lego.
type timeoutProvider struct {
	challenge.Provider
	timeout  time.Duration
	interval time.Duration
}

func (p timeoutProvider) Timeout() (time.Duration, time.Duration) {
	return p.timeout, p.interval
}
