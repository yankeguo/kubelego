package kube

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// NewClientset uses the in-cluster service account, and falls back to the
// kubeconfig loading rules when the process is not running in a pod.
func NewClientset() (kubernetes.Interface, error) {
	cfg, err := RestConfig()
	if err != nil {
		return nil, err
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("kubernetes client: %w", err)
	}
	return client, nil
}

// RestConfig builds a Kubernetes API config for this process.
func RestConfig() (*rest.Config, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		inClusterErr := err
		cfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			clientcmd.NewDefaultClientConfigLoadingRules(),
			&clientcmd.ConfigOverrides{},
		).ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("kubernetes config: in-cluster: %v; kubeconfig: %w", inClusterErr, err)
		}
	}
	cfg.UserAgent = "kubelego"
	cfg.QPS = 20
	cfg.Burst = 40
	return cfg, nil
}
