# Koyun WARP Relay v2

一个面板管理多台入口 VPS：每台入口机装一个 Agent，经 Cloudflare WARP 把流量转发到被墙的 Xboard 落地节点。

```text
                       ┌──────────── 控制端（面板）────────────┐
                       │ 节点 · 隧道 · 密钥池 · 规则 · 监控告警 │
                       │ 调用 Cloudflare WARP 接口注册/换密钥  │
                       └───────▲───────────────▲──────────────┘
                     HTTPS 同步│（每 5 秒）     │
              ┌────────────────┴──┐       ┌────┴──────────────┐
用户 ─TCP/UDP─>│ 入口节点 A（Agent）│  …   │ 入口节点 B（Agent）│
              └─────────┬─────────┘       └───────────────────┘
                        │ WARP（WireGuard）
                        ▼
                Cloudflare 边缘 ──> 落地节点（被墙 IP）
```

- **控制端**：唯一保存配置的地方。WARP 设备的注册、绑定密钥、刷新账户都在控制端完成，再把 WireGuard 参数下发给节点，所以节点在国内访问不了 Cloudflare API 也没关系。
- **Agent**：与控制端是同一个程序（`koyun-warp agent`）。它每 5 秒同步一次并上报状态，只重启参数有变化的隧道和规则。连不上控制端时，按本地缓存的配置继续转发。

## 添加一台入口 VPS

1. 面板「节点」→「新建节点」，填名称和入口地址（建议用仅 DNS 的域名）。
2. 复制弹出的一行命令，在 VPS 上用 root 执行：
   ```bash
   bash <(curl -fsSL 'https://面板域名/kw/i/kwi_xxx' || wget -qO- 'https://面板域名/kw/i/kwi_xxx')
   ```
3. 几秒后节点显示「在线」。到「WARP 隧道」为该节点新建隧道，到「转发规则」为该节点建规则。

安装命令 30 分钟内有效，Agent 第一次上线后作废。重新生成并执行安装命令会升级 Agent 并轮换令牌，旧令牌立即失效。支持 x86_64 / ARM64 的 systemd 系统。

| Agent 文件 | 用途 |
| --- | --- |
| `/opt/koyun-warp-agent/koyun-warp` | 程序 |
| `/etc/koyun-warp-agent/agent.env` | 控制端地址 + Agent 令牌（0600） |
| `/var/lib/koyun-warp-agent/config.json` | 最近一次配置的缓存 |
| `koyun-warp-agent.service` | systemd 服务，日志 `journalctl -u koyun-warp-agent -f` |

卸载：`systemctl disable --now koyun-warp-agent; rm -rf /opt/koyun-warp-agent /etc/koyun-warp-agent /var/lib/koyun-warp-agent /etc/systemd/system/koyun-warp-agent.service; systemctl daemon-reload`

## Cloudflare CDN 出站（WARP 的备用线路）

```text
用户 ─> 入口节点 ──WSS──> Cloudflare CDN ──> CDN 出口节点 ──TCP──> 落地节点
```

1. 选一台装了 Agent 的机器做出口（通常就是落地节点本身，或与它同机房的机器）。
2. 在 Cloudflare 加一条**橙色云朵**解析：`cdn.example.com → 出口机 IP`。
3. 面板「节点 → 编辑」该机器，勾选「CDN 出口」，填域名，端口选 443/2053/2083/2087/2096/8443 之一（不能与机器上已有服务冲突），出口机防火墙放行该端口。
4. SSL 模式：
   - 「灵活」或「完全」：不用证书，出口自动使用自签证书；
   - 「完全（严格）」：在 Cloudflare「SSL/TLS → 源服务器」创建源服务器证书（免费、15 年），把证书和私钥粘贴到节点设置里。
5. 规则的出站方式选「Cloudflare CDN」，再选出口节点。协议只能选 TCP。

优选 IP（可选，只影响「入口 → Cloudflare」这一段，每处可填多个，每行一个，最多 20 个）：
- 入口节点「编辑 → CDN 优选 IP」：只对这台入口生效，优先级最高；
- 出口节点「CDN 出口 → 默认优选 IP」：经这个出口、自己没设置的入口都用它；
- 都不填时按 CDN 域名的 DNS 解析。

填了多个 IP 时，新连接在其间轮询；某个 IP 连不上会立刻换下一个重试（每条连接最多试 3 个，单个最多等 4 秒），
失败的 IP 暂停 60 秒，连续失败时暂停时间翻倍，最长 10 分钟。各 IP 的成功 / 失败次数和建连延迟显示在入口节点的编辑窗口里。
多 IP 轮询需要 Agent 2.1.4 及以上；旧 Agent 只会用列表里的第一个 IP。海外入口一般不用填；国内入口在入口机上测速，并用 `curl --resolve 域名:端口:IP https://域名:端口/` 验证返回 404 后再填。

出口只允许连接面板下发的目标（即 CDN 规则里的目标），WebSocket 路径带随机密钥，其它请求一律返回 404。
每条连接都要新建一次 WSS 握手，所以建连比 WARP 慢 100～150ms，建好之后速度取决于 Cloudflare 线路。
免费 CDN 承载大流量代理有被 Cloudflare 限制的风险，建议作为 WARP 不可用时的备用线路。

## 域名建议

| 用途 | 建议 | 原因 |
| --- | --- | --- |
| 面板 / Agent 连接地址 | 域名 + Cloudflare 代理（橙色云朵）+ HTTPS | 面板 IP 被墙也能连；令牌加密传输；换机器只改 DNS |
| 节点入口地址 | 每台一个域名，**仅 DNS（灰色云朵）** | 转发端口不在 CDN 支持范围内；入口被墙时换机器只改解析，Xboard 不动 |

面板域名配好后，在「系统设置 → Agent 连接地址」填 `https://面板域名`，之后生成的安装命令都用这个地址。

## 构建与部署控制端

```bash
cd /root/CF转发
CGO_ENABLED=0 GOMAXPROCS=2 go build -p 1 -trimpath -ldflags "-s -w" -o build/koyun-warp .
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 GOMAXPROCS=2 go build -p 1 -trimpath -ldflags "-s -w" -o build/koyun-warp-linux-arm64 .
sudo deploy/install.sh build/koyun-warp 127.0.0.1:18991   # 反代时监听本地
```

Caddy 反代示例（接口都在 `/kw/` 下，避开 Cloudflare 对 `/api*` 的拦截）：

```caddyfile
warp.example.com {
	encode zstd gzip
	reverse_proxy 127.0.0.1:18991
}
```

### 迁移控制端

1. 旧机 `systemctl stop koyun-warp`。
2. 把 `/opt/koyun-warp/data/` 整个拷到新机同路径，在新机执行 `deploy/install.sh`。
3. 如果面板域名不变，只把 DNS 指到新机：所有 Agent 自动连上，无需重装。
4. 如果地址变了：在新面板「系统设置」改 Agent 连接地址，再到各节点点「重装命令」重新执行。

同一个 WARP 设备不能同时在两台机器上运行（两边握手会互相顶掉）。删除节点时会注销其上的 WARP 设备。

## 接入 Xboard

节点本身不动。Xboard 节点编辑：节点地址填入口节点的地址，连接端口填规则的监听端口，服务端端口保持节点原端口。

## 监控说明

- 隧道延迟 = 入口到 Cloudflare 边缘；目标探测 = 经规则的出站路径对目标做 TLS 握手。WARP 边缘会代答 TCP 握手，普通连通测试没有意义。
- 节点 30 秒未同步判为离线并告警；警告和错误可推送 Telegram。
- 流量由 Agent 上报累计值，控制端按差值累加并每分钟落盘。Agent 重启或控制端重启都不会重复计数。

## 已知限制

- 入口机自身 IP 必须能被大陆用户直连；WARP 只解决「入口 → 落地」这一段。
- 规则的监听端口冲突只能在节点上发现（面板会显示「监听失败」及原因）。
- 免费 WARP 属于个人用途服务，大流量商用可能被限速或封设备。
