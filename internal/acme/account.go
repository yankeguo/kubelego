package acme

import (
	"fmt"

	"github.com/go-acme/lego/v5/certcrypto"

	"github.com/yankeguo/kubelego/internal/state"
)

// accountPlan is the local half of account setup. Network calls happen only
// after the key, and any server change, have been saved.
type accountPlan struct {
	saveBeforeNetwork bool
	register          bool
	updateEmail       bool
}

// planAccount mutates st up to the point where a CA request is required.
// A new account key is stored on st before register is set, and a server
// change keeps the previously issued certificate so a failed reissue can
// still publish it.
func planAccount(st *state.State, email, server string) (accountPlan, error) {
	var plan accountPlan
	if st.Version == 0 {
		st.Version = state.Version
		plan.saveBeforeNetwork = true
	}

	if len(st.AccountKey) == 0 {
		key, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
		if err != nil {
			return accountPlan{}, fmt.Errorf("generate account key: %w", err)
		}
		st.AccountKey = certcrypto.PEMEncode(key)
		st.Registration = nil
		st.Certificate = nil
		st.Order = nil
		st.Email = email
		st.Server = server
		plan.saveBeforeNetwork = true
		plan.register = true
		return plan, nil
	}

	if st.Server != server {
		if st.Certificate != nil && st.Certificate.Server == "" && st.Server != "" {
			st.Certificate.Server = st.Server
		}
		st.Registration = nil
		st.Order = nil
		st.Server = server
		plan.saveBeforeNetwork = true
	}

	if st.Certificate != nil && st.Certificate.Server == "" && st.Server != "" {
		st.Certificate.Server = st.Server
		plan.saveBeforeNetwork = true
	}

	if st.Registration == nil {
		if st.Email != email {
			st.Email = email
			plan.saveBeforeNetwork = true
		}
		plan.register = true
		return plan, nil
	}

	if st.Email != email {
		plan.updateEmail = true
	}
	return plan, nil
}
