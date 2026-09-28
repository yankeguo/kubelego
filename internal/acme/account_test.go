package acme

import (
	"testing"

	"github.com/go-acme/lego/v5/acme"

	"github.com/yankeguo/kubelego/internal/state"
)

func TestPlanAccountSavesKeyBeforeRegister(t *testing.T) {
	st := &state.State{}
	plan, err := planAccount(st, "ops@example.com", "https://acme.example/directory")
	if err != nil {
		t.Fatal(err)
	}
	if !plan.saveBeforeNetwork || !plan.register || plan.updateEmail {
		t.Fatalf("plan = %+v", plan)
	}
	if len(st.AccountKey) == 0 || st.Registration != nil || st.Certificate != nil {
		t.Fatalf("state = %+v", st)
	}
	if st.Email != "ops@example.com" || st.Server != "https://acme.example/directory" {
		t.Fatalf("identity = %s %s", st.Email, st.Server)
	}
}

func TestPlanAccountKeepsCertificateWhenServerChanges(t *testing.T) {
	st := &state.State{
		Version:      state.Version,
		Email:        "ops@example.com",
		Server:       "https://old.example/directory",
		AccountKey:   []byte("key"),
		Registration: &acme.ExtendedAccount{Location: "https://old.example/acct/1"},
		Certificate:  &state.Certificate{Certificate: []byte("cert")},
		Order:        &state.Order{Location: "https://old.example/order/1"},
	}
	plan, err := planAccount(st, st.Email, "https://new.example/directory")
	if err != nil {
		t.Fatal(err)
	}
	if !plan.register || !plan.saveBeforeNetwork {
		t.Fatalf("plan = %+v", plan)
	}
	if st.Registration != nil || st.Order != nil {
		t.Fatal("old server registration and order were kept")
	}
	if st.Server != "https://new.example/directory" {
		t.Fatalf("server = %s", st.Server)
	}
	if string(st.Certificate.Certificate) != "cert" || st.Certificate.Server != "https://old.example/directory" {
		t.Fatalf("certificate = %+v", st.Certificate)
	}
}

func TestPlanAccountDoesNotPersistEmailBeforeUpdate(t *testing.T) {
	st := &state.State{
		Version:      state.Version,
		Email:        "old@example.com",
		Server:       "https://acme.example/directory",
		AccountKey:   []byte("key"),
		Registration: &acme.ExtendedAccount{Location: "https://acme.example/acct/1"},
	}
	plan, err := planAccount(st, "new@example.com", st.Server)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.updateEmail || plan.register || plan.saveBeforeNetwork {
		t.Fatalf("plan = %+v", plan)
	}
	if st.Email != "old@example.com" {
		t.Fatalf("email changed before the CA accepted it: %s", st.Email)
	}
}
