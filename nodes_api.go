package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
)

// ---------- 节点（面板） ----------

func validHost(h string) error {
	if h == "" {
		return nil
	}
	if len(h) > 253 {
		return errors.New("入口地址过长")
	}
	for _, c := range h {
		if !(c == '.' || c == '-' || c == ':' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return errors.New("入口地址只能是 IP 或域名")
		}
	}
	return nil
}

func (s *Server) listNodes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.nodeViews())
}

func installInfo(n *Node) map[string]any {
	return map[string]any{"id": n.ID, "name": n.Name, "install_token": n.InstallToken, "install_expires": n.InstallExpires}
}

func (s *Server) createNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string `json:"name"`
		PublicHost string `json:"public_host"`
		Remark     string `json:"remark"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, 400, err)
		return
	}
	req.Name, req.PublicHost, req.Remark = strings.TrimSpace(req.Name), strings.TrimSpace(req.PublicHost), strings.TrimSpace(req.Remark)
	if req.Name == "" || len(req.Name) > 64 {
		fail(w, 400, errors.New("请填写节点名称（不超过 64 字符）"))
		return
	}
	if err := validHost(req.PublicHost); err != nil {
		fail(w, 400, err)
		return
	}
	n, err := s.app.CreateNode(req.Name, req.PublicHost, req.Remark)
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, installInfo(n))
}

func (s *Server) patchNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Name         *string `json:"name"`
		PublicHost   *string `json:"public_host"`
		Remark       *string `json:"remark"`
		CDNEnabled   *bool   `json:"cdn_enabled"`
		CDNDomain    *string `json:"cdn_domain"`
		CDNPort      *int    `json:"cdn_port"`
		CDNConnectIP *string `json:"cdn_connect_ip"`
		CDNPreferIP  *string `json:"cdn_prefer_ip"`
		CDNCert      *string `json:"cdn_cert"`
		CDNKey       *string `json:"cdn_key"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, 400, err)
		return
	}
	if req.PublicHost != nil {
		*req.PublicHost = strings.TrimSpace(*req.PublicHost)
		if err := validHost(*req.PublicHost); err != nil {
			fail(w, 400, err)
			return
		}
	}
	if req.CDNPreferIP != nil {
		*req.CDNPreferIP = strings.TrimSpace(*req.CDNPreferIP)
		if *req.CDNPreferIP != "" && net.ParseIP(*req.CDNPreferIP) == nil {
			fail(w, 400, errors.New("CDN 优选 IP 格式不正确（只填 IP，不带端口）"))
			return
		}
	}
	err := s.app.store.Update(func(st *State) error {
		n := st.node(id)
		if n == nil {
			return errors.New("节点不存在")
		}
		if req.Name != nil && strings.TrimSpace(*req.Name) != "" {
			n.Name = strings.TrimSpace(*req.Name)
			n.Version++ // 名称会出现在 Agent 日志里
		}
		if req.PublicHost != nil {
			n.PublicHost = *req.PublicHost
		}
		if req.Remark != nil {
			n.Remark = strings.TrimSpace(*req.Remark)
		}
		if req.CDNPreferIP != nil && *req.CDNPreferIP != n.CDNPreferIP {
			n.CDNPreferIP = *req.CDNPreferIP
			n.Version++ // 只影响本节点作为入口时的 CDN 连接
		}
		if req.CDNEnabled != nil {
			if err := applyCDNSettings(st, n, req.CDNEnabled, req.CDNDomain, req.CDNPort, req.CDNConnectIP); err != nil {
				return err
			}
		}
		if req.CDNCert != nil {
			// 证书与私钥成对提交；两个都为空表示清除，改回自签证书
			c, k := strings.TrimSpace(*req.CDNCert), strings.TrimSpace(deref(req.CDNKey))
			if c != "" || k != "" {
				if _, err := tls.X509KeyPair([]byte(c), []byte(k)); err != nil {
					return fmt.Errorf("证书与私钥不匹配或格式错误：%v", err)
				}
			}
			n.CDNCert, n.CDNKey = c, k
			st.bumpAll()
		}
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// applyCDNSettings 校验并保存节点的 CDN 出口设置；任何变化都会让所有节点重新同步，
// 因为入口节点的连接地址和出口的目标白名单都依赖它。
func applyCDNSettings(st *State, n *Node, enabled *bool, domain *string, port *int, ip *string) error {
	if !*enabled {
		for _, r := range st.Rules {
			if r.Mode == "cdn" && r.CDNExitID == n.ID {
				return fmt.Errorf("规则「%s」正在经此节点走 CDN，请先修改规则再关闭 CDN 出口", r.Name)
			}
		}
		n.CDNEnabled = false
		st.bumpAll()
		return nil
	}
	d := strings.ToLower(strings.TrimSpace(deref(domain)))
	if d == "" || strings.ContainsAny(d, ":/ ") || validHost(d) != nil || !strings.Contains(d, ".") {
		return errors.New("请填写开了 Cloudflare 代理（橙色云朵）、指向本节点的域名")
	}
	p := 2096
	if port != nil {
		p = *port
	}
	if !cdnPorts[p] {
		return errors.New("CDN 端口必须是 Cloudflare 支持的 HTTPS 端口：443、2053、2083、2087、2096、8443")
	}
	cip := strings.TrimSpace(deref(ip))
	if cip != "" && net.ParseIP(cip) == nil {
		return errors.New("优选 IP 格式不正确")
	}
	for _, o := range st.Nodes {
		if o.ID != n.ID && o.CDNEnabled && o.CDNDomain == d {
			return fmt.Errorf("域名 %s 已被节点「%s」使用", d, o.Name)
		}
	}
	n.CDNEnabled, n.CDNDomain, n.CDNPort, n.CDNConnectIP = true, d, p, cip
	if n.CDNSecret == "" {
		n.CDNSecret = randHex(16)
	}
	st.bumpAll()
	return nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (s *Server) deleteNode(w http.ResponseWriter, r *http.Request) {
	if err := s.app.DeleteNode(r.PathValue("id")); err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) nodeInstall(w http.ResponseWriter, r *http.Request) {
	n, err := s.app.RegenInstall(r.PathValue("id"))
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, 200, installInfo(n))
}

// ---------- Agent 同步 ----------

func (s *Server) agentSync(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		fail(w, 401, errors.New("缺少 Agent 令牌"))
		return
	}
	n, found := s.app.nodeByToken(tok)
	if !found {
		fail(w, 401, errors.New("Agent 令牌无效（节点已删除或已在别处重装），请在面板重新生成安装命令"))
		return
	}
	var rep AgentReport
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20))
	if err := dec.Decode(&rep); err != nil {
		fail(w, 400, err)
		return
	}
	s.app.HandleReport(n, clientIP(r), rep)
	resp := syncResp{Version: n.Version}
	if rep.Applied != n.Version {
		resp.Config = s.app.BuildConfig(n.ID)
	}
	writeJSON(w, 200, resp)
}

// ---------- 一键安装 ----------

// panelBase 返回 Agent 应该连接的控制端地址：优先系统设置，其次按本次请求推断。
func (s *Server) panelBase(r *http.Request) string {
	if u := s.app.settings().PanelURL; u != "" {
		return u
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func shellSafe(v string) bool {
	return !strings.ContainsAny(v, "'\"`$\\\n\r ;&|<>(){}")
}

var installTmpl = template.Must(template.New("install").Parse(`#!/usr/bin/env bash
# Koyun WARP Relay Agent 安装脚本（由控制端生成，30 分钟内有效）
set -euo pipefail
SERVER='{{.Server}}'
INSTALL='{{.Install}}'
NODE='{{.Node}}'

say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m错误：\033[0m%s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "请用 root 运行"
command -v systemctl >/dev/null 2>&1 || die "需要 systemd"
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "不支持的 CPU 架构：$(uname -m)" ;;
esac

DIR=/opt/koyun-warp-agent
ETC=/etc/koyun-warp-agent
DATA=/var/lib/koyun-warp-agent
mkdir -p "$DIR" "$ETC" "$DATA"
chmod 700 "$ETC" "$DATA"

say "下载 Agent（$ARCH）"
TMP=$(mktemp "$DIR/.download.XXXXXX")
trap 'rm -f "$TMP"' EXIT
if command -v curl >/dev/null 2>&1; then
  curl -fsSL --retry 3 -o "$TMP" "$SERVER/kw/i/$INSTALL/bin/$ARCH" || die "下载失败"
elif command -v wget >/dev/null 2>&1; then
  wget -q --tries=3 -O "$TMP" "$SERVER/kw/i/$INSTALL/bin/$ARCH" || die "下载失败"
else
  die "需要 curl 或 wget"
fi
chmod 755 "$TMP"
"$TMP" -version >/dev/null 2>&1 || die "下载的程序无法运行（架构不符或文件损坏）"

systemctl stop koyun-warp-agent 2>/dev/null || true
mv -f "$TMP" "$DIR/koyun-warp"
trap - EXIT

# Agent 首次启动时用安装凭证向控制端换取永久令牌，保存在 $DATA/token；
# 重装时删除旧令牌，让新 Agent 重新注册。
rm -f "$DATA/token"
umask 077
cat > "$ETC/agent.env" <<EOF
KW_SERVER=$SERVER
KW_INSTALL=$INSTALL
EOF
umask 022

cat > /etc/systemd/system/koyun-warp-agent.service <<EOF
[Unit]
Description=Koyun WARP Relay Agent ($NODE)
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=$ETC/agent.env
ExecStart=$DIR/koyun-warp agent -data $DATA
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/sysctl.d/90-koyun-warp.conf <<'EOF'
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_fastopen = 3
EOF
sysctl -q --system >/dev/null 2>&1 || true

systemctl daemon-reload
systemctl enable --now koyun-warp-agent >/dev/null 2>&1
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do [ -s "$DATA/token" ] && break; sleep 1; done
if systemctl is-active --quiet koyun-warp-agent && [ -s "$DATA/token" ]; then
  say "安装完成，Agent 已启动。回到面板，几秒后节点会显示在线。"
  say "查看日志：journalctl -u koyun-warp-agent -f"
else
  journalctl -u koyun-warp-agent --no-pager -n 20 || true
  die "Agent 未能向控制端注册，请查看上面的日志（常见原因：本机连不上 $SERVER）"
fi
`))

func (s *Server) installScript(w http.ResponseWriter, r *http.Request) {
	inst := r.PathValue("token")
	n, err := s.app.nodeByInstall(inst)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(403)
		fmt.Fprintf(w, "echo '错误：%s' >&2; exit 1\n", strings.ReplaceAll(err.Error(), "'", ""))
		return
	}
	base := s.panelBase(r)
	name := strings.Map(func(c rune) rune {
		if strings.ContainsRune("'\"`$\\\n\r", c) {
			return -1
		}
		return c
	}, n.Name)
	if !shellSafe(base) || !shellSafe(inst) {
		fail(w, 400, errors.New("控制端地址包含非法字符"))
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	installTmpl.Execute(w, map[string]string{"Server": base, "Install": inst, "Node": name})
}

func (s *Server) agentRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InstallToken string `json:"install_token"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, 400, err)
		return
	}
	n, tok, err := s.app.IssueAgentToken(req.InstallToken)
	if err != nil {
		fail(w, 403, err)
		return
	}
	writeJSON(w, 200, map[string]string{"token": tok, "node_id": n.ID, "node_name": n.Name})
}

// installBinary 提供 Agent 程序：与控制端同架构时直接发送自身可执行文件，
// 其它架构从可执行文件旁的 bin/ 目录读取交叉编译产物。
func (s *Server) installBinary(w http.ResponseWriter, r *http.Request) {
	if !s.app.checkInstall(r.PathValue("token")) {
		fail(w, 403, errors.New("安装凭证无效或已过期"))
		return
	}
	arch := r.PathValue("arch")
	if arch != "amd64" && arch != "arm64" {
		fail(w, 400, errors.New("不支持的架构"))
		return
	}
	exe, err := os.Executable()
	if err != nil {
		fail(w, 500, err)
		return
	}
	path := exe
	if arch != runtime.GOARCH {
		path = filepath.Join(filepath.Dir(exe), "bin", "koyun-warp-linux-"+arch)
	}
	f, err := os.Open(path)
	if err != nil {
		fail(w, 404, fmt.Errorf("控制端没有 %s 架构的 Agent 程序", arch))
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprint(st.Size()))
	w.Header().Set("Cache-Control", "no-store")
	io.Copy(w, f)
}

// certInfo 返回证书的签发者与到期时间，用于面板展示。
func certInfo(pemText string) string {
	if pemText == "" {
		return ""
	}
	b, _ := pem.Decode([]byte(pemText))
	if b == nil {
		return "证书格式无法识别"
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return "证书格式无法识别"
	}
	return fmt.Sprintf("%s 签发，%s 到期", c.Issuer.CommonName, c.NotAfter.Format("2006-01-02"))
}
