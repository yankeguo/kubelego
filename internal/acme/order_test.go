package acme

import (
	"testing"

	"github.com/yankeguo/kubelego/internal/state"
)

func TestOrderMatches(t *testing.T) {
	order := &state.Order{
		Location:   "https://acme.example/order/1",
		Finalize:   "https://acme.example/order/1/finalize",
		Server:     "https://acme.example/directory",
		Domains:    []string{"Example.com", "*.example.com"},
		KeyType:    "EC256",
		PrivateKey: []byte("key"),
		CSR:        []byte("csr"),
	}
	if !orderMatches(order, []string{"example.com", "*.example.com"}, "ec256", order.Server) {
		t.Fatal("matching order was rejected")
	}
	if orderMatches(order, []string{"example.com"}, "EC256", order.Server) {
		t.Fatal("domain change still matched")
	}
	if orderMatches(order, order.Domains, "RSA2048", order.Server) {
		t.Fatal("key type change still matched")
	}
	if orderMatches(order, order.Domains, order.KeyType, "https://other.example/directory") {
		t.Fatal("server change still matched")
	}
	order.Location = ""
	if orderMatches(order, []string{"example.com", "*.example.com"}, "EC256", "https://acme.example/directory") {
		t.Fatal("order without a location matched")
	}
}
