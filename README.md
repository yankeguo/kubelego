# kubelego

[中文](README.zh.md)

A single Go binary that issues certificates inside a Kubernetes cluster. It calls [lego](https://go-acme.github.io/lego/) directly for DNS-01 validation and uses client-go to write account state and TLS Secrets through the API. It does not shell out to the `lego` or `kubectl` commands. Every DNS provider is linked into the binary, so the image is large.

Each Deployment owns one set of domains. The first domain is the certificate Common Name and the source of the default Secret name.

## How it runs

On startup the process:

1. Restores the ACME account from the state Secret. When there is no account key, it generates one, writes it to the Secret, and only then registers. The registration is saved before any certificate request.
2. Requests a new certificate when one is missing or when the domains or key type change. It renews when the certificate expires sooner than `KUBELEGO_RENEW_BEFORE`. The order URL, certificate private key, and CSR are written to the state Secret before DNS-01 starts.
3. Writes the certificate as a `kubernetes.io/tls` Secret. `tls.crt` is the leaf plus intermediates, `tls.key` is the private key, and `ca.crt` is the issuer certificate returned by the CA (the intermediate, plus the root when the CA returns that too).
4. Copies that TLS Secret into namespaces selected by glob, and deletes copies that kubelego created once they no longer match.

If the process stops at any of these steps, including on SIGTERM or an abrupt kill, the next start continues from the state Secret. The account key is not generated again. An unfinished order is validated or downloaded again. The order is dropped, and a new one is requested on the next reconcile, only when it is invalid, authorization fails, or the domains, key type, or ACME directory change. When a certificate has been issued but not yet stored, the next reconcile downloads it instead of opening another order. When it is stored but the TLS Secret has not been published, the next reconcile only publishes. A renewal that has not succeeded yet keeps publishing the certificate already on disk. After SIGTERM, the process still tries to finish the last state and TLS Secret write. The sample Deployment sets `terminationGracePeriodSeconds` to 60.

Reconcile runs once an hour by default. When the namespace list is non-empty, Namespace changes are watched, so a new namespace receives a copy without waiting for the next renewal check. Keep `replicas` at 1. The sample uses `Recreate` so two processes do not place orders at the same time.

## Environment variables

| Variable | Required | Description |
| --- | --- | --- |
| `KUBELEGO_EMAIL` | yes | ACME account email |
| `KUBELEGO_ACCEPT_TOS` | yes | Must be `true` to accept the CA terms of service |
| `KUBELEGO_DOMAINS` | yes | Comma-separated domains. The first is the certificate Common Name and the source of the default Secret name |
| `KUBELEGO_DNS_PROVIDER` | yes | lego DNS provider name, the same value as `lego --dns`, including every built-in provider and alias |
| `KUBELEGO_STATE_SECRET` | no | Secret that stores account and certificate state, as `name` or `namespace/name`. Defaults to `<current namespace>/<first domain>-state`. Dots and other separators in the domain become `-` |
| `KUBELEGO_CERT_SECRET` | no | TLS Secret, same form as above. Defaults to `<current namespace>/<first domain>`, with the same separator replacement |
| `KUBELEGO_CERT_NAMESPACES` | no | Comma-separated namespace globs. `*` matches any length, `?` matches one character. `*` alone means every namespace |
| `KUBELEGO_SERVER` | no | ACME directory URL, or a lego CA code (`letsencrypt`, `letsencrypt-staging`, `zerossl`, and so on). Defaults to Let's Encrypt production |
| `KUBELEGO_KEY_TYPE` | no | `ec256` (default), `ec384`, `rsa2048`, `rsa3072`, `rsa4096`, `rsa8192` |
| `KUBELEGO_RENEW_BEFORE` | no | How early to renew. Accepts a Go duration or a day count such as `30d`. Defaults to `30d` |
| `KUBELEGO_INTERVAL` | no | Reconcile interval. Defaults to `1h`, minimum `1m`. `0` runs once |
| `KUBELEGO_ONCE` | no | When `true`, issue or renew once and exit. Suited to a CronJob |
| `KUBELEGO_DNS_RESOLVERS` | no | Comma-separated recursive resolvers, for example `1.1.1.1,8.8.8.8:53`. Defaults to the Pod's system resolver |
| `KUBELEGO_DNS_TIMEOUT` | no | How long to wait for DNS-01 propagation. When unset, the provider's own timeout is used |
| `KUBELEGO_EAB_KID` / `KUBELEGO_EAB_HMAC` | no | External Account Binding for CAs that require it. ZeroSSL without these two uses lego's ZeroSSL registration |
| `KUBELEGO_NAMESPACE` | no | Namespace used when a Secret reference omits one. Defaults to the Pod ServiceAccount namespace |

`example.com` becomes the Secret name `example-com`, and `*.example.com` becomes `wildcard-example-com`. An explicit `KUBELEGO_CERT_SECRET` or `KUBELEGO_STATE_SECRET` is used as written and is not passed through that replacement.

`KUBELEGO_DNS_PROVIDER` is passed to lego's `NewDNSChallengeProviderByName`, the same factory the lego CLI uses. Names are case-insensitive, and aliases work, for example `cloudflare`, `route53`, `alidns`, `rfc2136`, and `acme-dns`. Credentials are that provider's own environment variables, such as Cloudflare's `CLOUDFLARE_DNS_API_TOKEN`. Route 53 can also use its default AWS credential chain. The full list of names and variables is in the [lego DNS providers](https://go-acme.github.io/lego/dns/) documentation.

`manual` needs interactive input and cannot finish in a Pod. `exec` is included in the binary, but the image must also contain the program named by `EXEC_PATH`. The current image is distroless and has no shell.

## Secrets

The state Secret is Opaque. Its data key is `state.json`, which holds the ACME account key, registration, any unfinished order, and the issued certificate. The TLS Secret is what workloads mount.

kubelego updates only Secrets labeled `app.kubernetes.io/managed-by=kubelego`. A Secret with the same name that kubelego did not create is left in place, and the error is logged. Copies in other namespaces use the same Secret name. A copy's `kubelego.io/source` annotation points at the primary Secret. When a namespace no longer matches, only copies with that source annotation are deleted.

## Deploy

```bash
kubectl apply -f deploy/rbac.yaml
kubectl apply -f deploy/deployment.yaml
```

`deploy/rbac.yaml` is a ClusterRole: list namespaces, and read and write Secrets in any namespace. When certificates are not copied, narrow it to a Role in the namespace of the primary Secret.

Build the image:

```bash
docker build -t ghcr.io/yankeguo/kubelego:latest .
```

Check locally:

```bash
go test ./...
go build -o bin/kubelego ./cmd/kubelego
```

## License

MIT. See [LICENSE](LICENSE).
