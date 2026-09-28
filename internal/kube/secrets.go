package kube

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/yankeguo/kubelego/internal/cert"
	"github.com/yankeguo/kubelego/internal/config"
	"github.com/yankeguo/kubelego/internal/pattern"
	"github.com/yankeguo/kubelego/internal/state"
)

const (
	labelManagedBy = "app.kubernetes.io/managed-by"
	managedBy      = "kubelego"
	labelName      = "app.kubernetes.io/name"
	labelComponent = "app.kubernetes.io/component"

	annotationSource   = "kubelego.io/source"
	annotationDomains  = "kubelego.io/domains"
	annotationNotAfter = "kubelego.io/not-after"

	stateKey = "state.json"
)

// LoadState reads the ACME state secret. A missing secret is an empty state.
func LoadState(ctx context.Context, client kubernetes.Interface, ref config.SecretRef) (*state.State, error) {
	secret, err := client.CoreV1().Secrets(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return &state.State{Version: state.Version}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get state secret %s: %w", ref, err)
	}
	if !owned(secret) {
		return nil, fmt.Errorf("state secret %s exists and is not managed by kubelego", ref)
	}
	raw := secret.Data[stateKey]
	if len(raw) == 0 {
		return nil, fmt.Errorf("state secret %s has no %s", ref, stateKey)
	}
	st, err := state.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("state secret %s: %w", ref, err)
	}
	return st, nil
}

// SaveState writes the ACME state secret.
func SaveState(ctx context.Context, client kubernetes.Interface, ref config.SecretRef, domains []string, st *state.State) error {
	raw, err := st.Marshal()
	if err != nil {
		return err
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ref.Namespace,
			Name:      ref.Name,
			Labels: map[string]string{
				labelManagedBy: managedBy,
				labelName:      "kubelego",
				labelComponent: "account",
			},
			Annotations: map[string]string{
				annotationDomains: strings.Join(domains, ","),
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{stateKey: raw},
	}
	if err := upsert(ctx, client, secret); err != nil {
		return fmt.Errorf("save state secret %s: %w", ref, err)
	}
	return nil
}

// Publish writes the primary TLS secret and copies it into namespaces selected
// by patterns. Copies that this process created, and that no longer match, are removed.
func Publish(ctx context.Context, client kubernetes.Interface, ref config.SecretRef, domains, patterns []string, mat cert.Material) error {
	desired := tlsSecret(ref, domains, ref.String(), mat)
	if err := upsert(ctx, client, desired); err != nil {
		return fmt.Errorf("save tls secret %s: %w", ref, err)
	}
	if err := replicate(ctx, client, ref, desired, patterns); err != nil {
		return fmt.Errorf("replicate tls secret %s: %w", ref, err)
	}
	return nil
}

func tlsSecret(ref config.SecretRef, domains []string, source string, mat cert.Material) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ref.Namespace,
			Name:      ref.Name,
			Labels: map[string]string{
				labelManagedBy: managedBy,
				labelName:      "kubelego",
				labelComponent: "certificate",
			},
			Annotations: map[string]string{
				annotationSource:   source,
				annotationDomains:  strings.Join(domains, ","),
				annotationNotAfter: mat.NotAfter.UTC().Format(time.RFC3339),
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       mat.TLSCrt,
			corev1.TLSPrivateKeyKey: mat.TLSKey,
			"ca.crt":                mat.CACrt,
		},
	}
}

func replicate(ctx context.Context, client kubernetes.Interface, primary config.SecretRef, desired *corev1.Secret, patterns []string) error {
	if len(patterns) == 0 {
		return nil
	}
	list, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list namespaces: %w", err)
	}

	source := primary.String()
	matched := make(map[string]bool, len(list.Items))
	var errs []error
	for _, ns := range list.Items {
		if ns.DeletionTimestamp != nil {
			continue
		}
		ok, err := pattern.Matches(ns.Name, patterns)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !ok {
			continue
		}
		matched[ns.Name] = true
		if ns.Name == primary.Namespace {
			continue
		}
		copy := desired.DeepCopy()
		copy.Namespace = ns.Name
		copy.ResourceVersion = ""
		if err := upsert(ctx, client, copy); err != nil {
			errs = append(errs, fmt.Errorf("copy tls secret to %s: %w", ns.Name, err))
		}
	}

	for _, ns := range list.Items {
		if matched[ns.Name] || ns.Name == primary.Namespace || ns.DeletionTimestamp != nil {
			continue
		}
		if err := deleteReplica(ctx, client, ns.Name, desired.Name, source); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func deleteReplica(ctx context.Context, client kubernetes.Interface, namespace, name, source string) error {
	secret, err := client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("get tls secret %s/%s: %w", namespace, name, err)
	}
	if !owned(secret) || secret.Annotations[annotationSource] != source {
		return nil
	}
	if err := client.CoreV1().Secrets(namespace).Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete tls secret %s/%s: %w", namespace, name, err)
	}
	return nil
}

func upsert(ctx context.Context, client kubernetes.Interface, desired *corev1.Secret) error {
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		err = upsertOnce(ctx, client, desired)
		if err == nil || !apierrors.IsConflict(err) {
			return err
		}
	}
	return err
}

func upsertOnce(ctx context.Context, client kubernetes.Interface, desired *corev1.Secret) error {
	secrets := client.CoreV1().Secrets(desired.Namespace)
	existing, err := secrets.Get(ctx, desired.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		created := desired.DeepCopy()
		created.ResourceVersion = ""
		_, err = secrets.Create(ctx, created, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	if !owned(existing) {
		return fmt.Errorf("secret %s/%s exists and is not managed by kubelego", desired.Namespace, desired.Name)
	}
	existing.Type = desired.Type
	existing.Data = desired.Data
	if existing.Labels == nil {
		existing.Labels = map[string]string{}
	}
	for key, value := range desired.Labels {
		existing.Labels[key] = value
	}
	if existing.Annotations == nil {
		existing.Annotations = map[string]string{}
	}
	for key, value := range desired.Annotations {
		existing.Annotations[key] = value
	}
	_, err = secrets.Update(ctx, existing, metav1.UpdateOptions{})
	return err
}

func owned(secret *corev1.Secret) bool {
	return secret.Labels[labelManagedBy] == managedBy
}
