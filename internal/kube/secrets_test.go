package kube

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/yankeguo/kubelego/internal/cert"
	"github.com/yankeguo/kubelego/internal/config"
	"github.com/yankeguo/kubelego/internal/state"
)

func TestPublishCopiesAndDeletesReplicas(t *testing.T) {
	now := time.Now()
	client := fake.NewSimpleClientset(
		namespace("certs", false),
		namespace("app-1", false),
		namespace("app-2", false),
		namespace("app-gone", true),
		namespace("legacy", false),
		namespace("keep", false),
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "legacy",
				Name:      "example.com",
				Labels:    map[string]string{labelManagedBy: managedBy},
				Annotations: map[string]string{
					annotationSource: "certs/example.com",
				},
			},
			Type: corev1.SecretTypeTLS,
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "keep",
				Name:      "example.com",
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{"other": []byte("leave-me")},
		},
	)

	ref := config.SecretRef{Namespace: "certs", Name: "example.com"}
	mat := cert.Material{
		TLSCrt:   []byte("crt\n"),
		TLSKey:   []byte("key\n"),
		CACrt:    []byte("ca\n"),
		NotAfter: now.Add(24 * time.Hour),
	}
	err := Publish(context.Background(), client, ref, []string{"example.com", "*.example.com"}, []string{"app-*"}, mat)
	if err != nil {
		t.Fatal(err)
	}

	primary, err := client.CoreV1().Secrets("certs").Get(context.Background(), "example.com", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if primary.Type != corev1.SecretTypeTLS || string(primary.Data[corev1.TLSCertKey]) != "crt\n" || string(primary.Data["ca.crt"]) != "ca\n" {
		t.Fatalf("primary = %#v", primary.Data)
	}

	for _, ns := range []string{"app-1", "app-2"} {
		secret, err := client.CoreV1().Secrets(ns).Get(context.Background(), "example.com", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("%s: %v", ns, err)
		}
		if secret.Annotations[annotationSource] != "certs/example.com" || string(secret.Data[corev1.TLSPrivateKeyKey]) != "key\n" {
			t.Fatalf("%s secret was not a replica: %#v", ns, secret)
		}
	}

	if _, err := client.CoreV1().Secrets("app-gone").Get(context.Background(), "example.com", metav1.GetOptions{}); err == nil {
		t.Fatal("copied into a terminating namespace")
	}
	if _, err := client.CoreV1().Secrets("legacy").Get(context.Background(), "example.com", metav1.GetOptions{}); err == nil {
		t.Fatal("stale replica was not deleted")
	}
	kept, err := client.CoreV1().Secrets("keep").Get(context.Background(), "example.com", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(kept.Data["other"]) != "leave-me" {
		t.Fatal("unmanaged secret was modified")
	}
}

func TestPublishRefusesUnmanagedSecret(t *testing.T) {
	client := fake.NewSimpleClientset(
		namespace("certs", false),
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "certs", Name: "example.com"},
			Type:       corev1.SecretTypeTLS,
		},
	)
	err := Publish(context.Background(), client, config.SecretRef{Namespace: "certs", Name: "example.com"}, []string{"example.com"}, nil, cert.Material{})
	if err == nil {
		t.Fatal("expected a refusal to overwrite an unmanaged secret")
	}
}

func TestStateRoundTrip(t *testing.T) {
	client := fake.NewSimpleClientset()
	ref := config.SecretRef{Namespace: "kubelego", Name: "example.com-state"}
	original := &state.State{Version: state.Version, Email: "ops@example.com", AccountKey: []byte("key")}
	if err := SaveState(context.Background(), client, ref, []string{"example.com"}, original); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(context.Background(), client, ref)
	if err != nil {
		t.Fatal(err)
	}
	if got.Email != original.Email || string(got.AccountKey) != "key" {
		t.Fatalf("state = %+v", got)
	}
}

func namespace(name string, terminating bool) *corev1.Namespace {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if terminating {
		ts := metav1.Now()
		ns.DeletionTimestamp = &ts
	}
	return ns
}
