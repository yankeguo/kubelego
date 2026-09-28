// Package app runs the certificate reconcile loop.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/yankeguo/kubelego/internal/acme"
	"github.com/yankeguo/kubelego/internal/cert"
	"github.com/yankeguo/kubelego/internal/config"
	"github.com/yankeguo/kubelego/internal/issue"
	"github.com/yankeguo/kubelego/internal/kube"
	"github.com/yankeguo/kubelego/internal/state"
)

// Run reconciles one certificate until ctx is canceled.
// With Config.Once, it reconciles a single time and returns.
func Run(ctx context.Context, cfg config.Config) error {
	client, err := kube.NewClientset()
	if err != nil {
		return err
	}
	slog.Info("starting",
		"domains", strings.Join(cfg.Domains, ","),
		"dnsProvider", cfg.DNSProvider,
		"server", cfg.Server,
		"certSecret", cfg.CertSecret.String(),
		"stateSecret", cfg.StateSecret.String(),
		"namespaces", strings.Join(cfg.Namespaces, ","),
		"once", cfg.Once,
		"interval", cfg.Interval.String(),
	)

	runner := &runner{
		client: client,
		cfg:    cfg,
		svc: issue.Service{
			ACME: &acme.Client{
				Provider:  cfg.DNSProvider,
				Resolvers: cfg.DNSResolvers,
				Timeout:   cfg.DNSTimeout,
			},
			Save: func(ctx context.Context, st *state.State) error {
				return kube.SaveState(ctx, client, cfg.StateSecret, cfg.Domains, st)
			},
			Email:       cfg.Email,
			Server:      cfg.Server,
			EABKID:      cfg.EABKID,
			EABHMAC:     cfg.EABHMAC,
			Domains:     cfg.Domains,
			KeyType:     cfg.KeyType,
			RenewBefore: cfg.RenewBefore,
		},
		syncCh: make(chan struct{}, 1),
	}
	return runner.run(ctx)
}

type runner struct {
	client kubernetes.Interface
	cfg    config.Config
	svc    issue.Service
	syncCh chan struct{}

	mu       sync.Mutex
	material cert.Material
	ready    bool
}

func (r *runner) run(ctx context.Context) error {
	if r.cfg.Once {
		return r.reconcile(ctx)
	}
	if err := r.watchNamespaces(ctx); err != nil {
		return err
	}
	for {
		if err := r.reconcile(ctx); err != nil {
			slog.Error("reconcile failed", "err", err)
			if err := r.wait(ctx, time.Minute); err != nil {
				return nil
			}
			continue
		}
		if err := r.wait(ctx, r.cfg.Interval); err != nil {
			return nil
		}
	}
}

func (r *runner) reconcile(ctx context.Context) error {
	st, err := kube.LoadState(ctx, r.client, r.cfg.StateSecret)
	if err != nil {
		return err
	}
	mat, err := r.svc.Sync(ctx, st)
	if err != nil {
		return err
	}
	r.setMaterial(mat)
	return kube.Publish(ctx, r.client, r.cfg.CertSecret, r.cfg.Domains, r.cfg.Namespaces, mat)
}

func (r *runner) syncOnly(ctx context.Context) error {
	mat, ok := r.current()
	if !ok {
		return nil
	}
	return kube.Publish(ctx, r.client, r.cfg.CertSecret, r.cfg.Domains, r.cfg.Namespaces, mat)
}

func (r *runner) watchNamespaces(ctx context.Context) error {
	if len(r.cfg.Namespaces) == 0 {
		return nil
	}
	factory := informers.NewSharedInformerFactory(r.client, 10*time.Minute)
	_, err := factory.Core().V1().Namespaces().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { r.poke() },
		UpdateFunc: func(any, any) { r.poke() },
		DeleteFunc: func(any) { r.poke() },
	})
	if err != nil {
		return fmt.Errorf("watch namespaces: %w", err)
	}
	factory.Start(ctx.Done())
	return nil
}

func (r *runner) poke() {
	select {
	case r.syncCh <- struct{}{}:
	default:
	}
}

func (r *runner) wait(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		case <-r.syncCh:
			if err := r.syncOnly(ctx); err != nil {
				slog.Error("namespace sync failed", "err", err)
			}
		}
	}
}

func (r *runner) setMaterial(mat cert.Material) {
	r.mu.Lock()
	r.material = mat
	r.ready = true
	r.mu.Unlock()
}

func (r *runner) current() (cert.Material, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.material, r.ready
}
