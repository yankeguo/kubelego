# kubelego

[English](README.md)

在 Kubernetes 集群内申请证书的单个 Go 二进制。它直接调用 [lego](https://go-acme.github.io/lego/) 完成 DNS-01 校验，并用 client-go 把账号状态和 TLS Secret 写进 API，不依赖 `lego` 或 `kubectl` 命令。DNS provider 全部编进这个二进制，所以镜像会比较大。

每个 Deployment 负责一组域名。第一个域名是证书的 Common Name，也是默认 Secret 名称的来源。

## 运行方式

进程启动后会：

1. 从状态 Secret 恢复 ACME 账号。没有账号私钥时先生成并写入 Secret，再注册；注册结果也会先落盘，然后才申请证书。
2. 证书缺失、域名或密钥类型变化时重新申请；距离过期时间小于 `KUBELEGO_RENEW_BEFORE` 时续期。订单 URL、证书私钥和 CSR 会在 DNS-01 之前写入状态 Secret。
3. 把证书写成 `kubernetes.io/tls` Secret。`tls.crt` 是叶子证书加中间证书，`tls.key` 是私钥，`ca.crt` 是 CA 返回的签发证书（中间证书，CA 同时返回根证书时也包含根证书）。
4. 按命名空间通配把同一份 TLS Secret 复制出去，并删掉不再匹配、且由 kubelego 创建的副本。

进程在这些步骤的任意一点停止，包括收到 SIGTERM 或被直接杀掉，重启后都会从状态 Secret 接着做完。账号私钥不会重新生成。未完成的订单会继续校验或下载；订单失效、授权失败，或者域名、密钥类型、ACME 目录变了，才会丢掉它并在下一轮重新申请。证书已经签发但还没写进 TLS Secret 时，下一轮只发布，不再向 CA 下单。续期还没成功时，已经保存的证书会继续发布。SIGTERM 之后仍会尽量把已经得到的状态和 TLS Secret 写完。示例 Deployment 的 `terminationGracePeriodSeconds` 是 60。

默认每小时对账一次。命名空间列表非空时，还会监听 Namespace 变化，新命名空间不用等到下一轮续期检查就会拿到副本。`replicas` 请保持为 1，示例里使用 `Recreate`，避免两个进程同时向 CA 下单。

## 环境变量

| 变量 | 必填 | 说明 |
| --- | --- | --- |
| `KUBELEGO_EMAIL` | 是 | ACME 账号邮箱 |
| `KUBELEGO_ACCEPT_TOS` | 是 | 必须为 `true`，表示接受 CA 服务条款 |
| `KUBELEGO_DOMAINS` | 是 | 逗号分隔的域名。第一个域名作为证书 Common Name，并生成默认 Secret 名 |
| `KUBELEGO_DNS_PROVIDER` | 是 | lego 的 DNS provider 名称，与 `lego --dns` 相同，包含全部内置 provider 和别名 |
| `KUBELEGO_STATE_SECRET` | 否 | 保存账号和证书状态的 Secret，`name` 或 `namespace/name`。默认 `<当前命名空间>/<第一个域名>-state`，域名里的 `.` 和其他分隔符会换成 `-` |
| `KUBELEGO_CERT_SECRET` | 否 | TLS Secret，格式同上。默认 `<当前命名空间>/<第一个域名>`，同样把分隔符换成 `-` |
| `KUBELEGO_CERT_NAMESPACES` | 否 | 逗号分隔的命名空间通配。`*` 匹配任意长度，`?` 匹配一个字符。`*` 表示所有命名空间 |
| `KUBELEGO_SERVER` | 否 | ACME 目录 URL，或 lego 的 CA 代码（`letsencrypt`、`letsencrypt-staging`、`zerossl` 等）。默认 Let's Encrypt 生产环境 |
| `KUBELEGO_KEY_TYPE` | 否 | `ec256`（默认）、`ec384`、`rsa2048`、`rsa3072`、`rsa4096`、`rsa8192` |
| `KUBELEGO_RENEW_BEFORE` | 否 | 提前多久续期。支持 Go duration，也支持 `30d` 这种天数。默认 `30d` |
| `KUBELEGO_INTERVAL` | 否 | 对账间隔，默认 `1h`，至少 `1m`。`0` 表示只运行一次 |
| `KUBELEGO_ONCE` | 否 | `true` 时只申请或续期一次后退出，适合 CronJob |
| `KUBELEGO_DNS_RESOLVERS` | 否 | 逗号分隔的递归解析器，例如 `1.1.1.1,8.8.8.8:53`。默认使用 Pod 的系统解析器 |
| `KUBELEGO_DNS_TIMEOUT` | 否 | DNS-01 传播等待时间。不设置时使用 provider 自己的超时 |
| `KUBELEGO_EAB_KID` / `KUBELEGO_EAB_HMAC` | 否 | 需要 External Account Binding 的 CA。ZeroSSL 未设置这两项时，沿用 lego 的 ZeroSSL 注册方式 |
| `KUBELEGO_NAMESPACE` | 否 | Secret 引用里省略命名空间时使用的命名空间。默认读取 Pod ServiceAccount 的命名空间 |

`example.com` 会得到 Secret 名 `example-com`，`*.example.com` 会得到 `wildcard-example-com`。显式设置 `KUBELEGO_CERT_SECRET` 或 `KUBELEGO_STATE_SECRET` 时，名称原样使用，不再经过这层替换。

`KUBELEGO_DNS_PROVIDER` 会原样交给 lego 的 `NewDNSChallengeProviderByName`，也就是 lego CLI 使用的那份完整工厂。名称不区分大小写，别名同样可用，例如 `cloudflare`、`route53`、`alidns`、`rfc2136`、`acme-dns`。凭证使用该 provider 自己的环境变量，例如 Cloudflare 的 `CLOUDFLARE_DNS_API_TOKEN`；Route 53 也可以走它默认的 AWS 凭证链。名称和变量的完整列表见 [lego DNS providers](https://go-acme.github.io/lego/dns/)。

`manual` 需要交互输入，在 Pod 里无法完成。`exec` 已包含在二进制里，但还要镜像里存在 `EXEC_PATH` 指向的程序；当前镜像基于 distroless，没有 shell。

## Secret

状态 Secret 是 Opaque，数据键为 `state.json`，里面有 ACME 账号私钥、注册信息、未完成的订单和已签发证书。TLS Secret 才是工作负载要挂载的对象。

kubelego 只会更新带 `app.kubernetes.io/managed-by=kubelego` 的 Secret。同名但不是它创建的 Secret 会保留，并在日志里报错。复制到其他命名空间时使用相同的 Secret 名称；副本的 `kubelego.io/source` 指向主 Secret。通配不再匹配时，只删除带这个来源注解的副本。

## 部署

```bash
kubectl apply -f deploy/rbac.yaml
kubectl apply -f deploy/deployment.yaml
```

`deploy/rbac.yaml` 是一组 ClusterRole：列出命名空间，并在任意命名空间读写 Secret。不需要复制证书时，可以收成主 Secret 所在命名空间的 Role。

构建镜像：

```bash
docker build -t ghcr.io/yankeguo/kubelego:latest .
```

本地检查：

```bash
go test ./...
go build -o bin/kubelego ./cmd/kubelego
```

## 许可

MIT，见 [LICENSE](LICENSE)。
