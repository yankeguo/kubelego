package acme

import (
	"crypto"

	legocme "github.com/go-acme/lego/v5/acme"
)

type user struct {
	email string
	key   crypto.Signer
	reg   *legocme.ExtendedAccount
}

func (u *user) GetEmail() string { return u.email }

func (u *user) GetRegistration() *legocme.ExtendedAccount { return u.reg }

func (u *user) GetPrivateKey() crypto.Signer { return u.key }
