package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// CDNLine 记录一条「用户 → Cloudflare → 落地节点」的接入线路。
// 用户直接连 Cloudflare，适合入口和落地 IP 都被墙的情况；流量不经过任何 Agent，
// 面板只负责记录配置、生成 Xboard 填写项和定时检测。
type CDNLine struct {
	ID        string       `json:"id"`
	Name      string       `json:"name"`
	Protocol  string       `json:"protocol"` // trojan | vless | vmess，仅用于展示
	Origin    string       `json:"origin"`   // 落地节点 IP 或域名
	Port      int          `json:"port"`     // 用户连接端口，也是 Cloudflare 回源端口
	Domain    string       `json:"domain"`   // 橙色云朵域名，填在 SNI 与 Host
	Path      string       `json:"path"`     // WebSocket 路径
	Address   string       `json:"address"`  // 用户连接地址（灰色云朵的优选域名），可空
	IPs       []string     `json:"ips"`      // 优选 IP，应与 Address 的 A 记录一致
	Remark    string       `json:"remark"`
	CreatedAt int64        `json:"created_at"`
	Test      *CDNLineTest `json:"test,omitempty"`
}

type CDNLineTest struct {
	At     int64         `json:"at"`
	OK     bool          `json:"ok"` // 所有优选 IP 都可用
	Checks []CDNCheck    `json:"checks"`
	Items  []CDNTestItem `json:"items"`
}

// CDNCheck 是 DNS、配置类检查的结论。
type CDNCheck struct {
	Level string `json:"level"` // ok | warn | bad
	Msg   string `json:"msg"`
}

// CDNTestItem 是一次 WebSocket 握手的结果。
type CDNTestItem struct {
	Kind   string `json:"kind"` // origin | ip | dns
	Target string `json:"target"`
	OK     bool   `json:"ok"`
	Ms     int64  `json:"ms"`
	Colo   string `json:"colo"`
	Msg    string `json:"msg"`
}

// Cloudflare 公布的 IPv4 段，用来判断域名是否开了橙色云朵。
var cfNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
		"108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15",
		"104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

func isCFIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	if ip.To4() == nil {
		return strings.HasPrefix(ip.String(), "2606:4700:") || strings.HasPrefix(ip.String(), "2a06:98c")
	}
	for _, n := range cfNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func lookupV4(ctx context.Context, host string) ([]string, error) {
	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	sort.Strings(out)
	return out, nil
}

// wsProbe 连接 addr，用 sni 做 TLS 握手，再以 host 和 path 发起 WebSocket 升级，返回 101 才算成功。
func wsProbe(ctx context.Context, addr, sni, host, path string, verify bool) CDNTestItem {
	start := time.Now()
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{ServerName: sni, NextProtos: []string{"http/1.1"}, InsecureSkipVerify: !verify},
		ForceAttemptHTTP2: false,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	defer tr.CloseIdleConnections()
	ws, resp, err := websocket.Dial(ctx, "wss://"+host+path, &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: tr}, Host: host, CompressionMode: websocket.CompressionDisabled,
		HTTPHeader: http.Header{"User-Agent": {"Mozilla/5.0"}},
	})
	it := CDNTestItem{Ms: time.Since(start).Milliseconds()}
	if resp != nil {
		if ray := resp.Header.Get("Cf-Ray"); strings.Contains(ray, "-") {
			it.Colo = ray[strings.LastIndex(ray, "-")+1:]
		}
	}
	if err == nil {
		ws.CloseNow()
		it.OK, it.Msg = true, "WebSocket 握手成功（101）"
		return it
	}
	switch {
	case resp == nil:
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded) {
			it.Msg = "超时：这个 IP 连不上"
		} else if strings.Contains(err.Error(), "connection reset") {
			it.Msg = "连接被重置：这个 IP 不为该域名提供服务（常见于 172.65.x 等段），换一个优选 IP"
		} else if strings.Contains(err.Error(), "certificate") {
			it.Msg = "证书校验失败：" + shortErr(err)
		} else {
			it.Msg = shortErr(err)
		}
	case resp.StatusCode == 404:
		it.Msg = "404：WS 路径与落地节点不一致（或落地节点未启用 WS）"
	case resp.StatusCode == 400:
		it.Msg = "400：落地节点拒绝了请求，检查传输协议是否为 WS"
	case resp.StatusCode == 403:
		it.Msg = "403：这个 IP 不为该域名提供服务，换一个优选 IP"
	case resp.StatusCode >= 520 && resp.StatusCode <= 524:
		it.Msg = fmt.Sprintf("Cloudflare %d：连不上落地节点的 %s 端口", resp.StatusCode, portOf(addr))
	case resp.StatusCode == 525 || resp.StatusCode == 526:
		it.Msg = fmt.Sprintf("Cloudflare %d：回源 TLS 失败。SSL 模式为「完全（严格）」时，落地证书必须对该域名有效", resp.StatusCode)
	default:
		it.Msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return it
}

func portOf(addr string) string {
	_, p, _ := net.SplitHostPort(addr)
	return p
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s) > 120 {
		s = s[i+2:]
	}
	return s
}

// TestCDNLine 检查 DNS 配置，并对落地节点和每个优选 IP 做 WebSocket 握手。
func TestCDNLine(l CDNLine) *CDNLineTest {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	t := &CDNLineTest{At: time.Now().Unix(), Checks: []CDNCheck{}, Items: []CDNTestItem{}}
	add := func(level, f string, a ...any) { t.Checks = append(t.Checks, CDNCheck{level, fmt.Sprintf(f, a...)}) }
	port := fmt.Sprint(l.Port)

	if ips, err := lookupV4(ctx, l.Domain); err != nil {
		add("bad", "域名 %s 解析失败：%s。请在 Cloudflare 添加 A 记录指向 %s 并开启橙色云朵", l.Domain, shortErr(err), l.Origin)
	} else if len(ips) == 0 || !isCFIP(ips[0]) {
		add("bad", "域名 %s 解析到 %s，不是 Cloudflare 的 IP：请把这条记录的云朵点成橙色", l.Domain, strings.Join(ips, " "))
	} else {
		add("ok", "域名 %s 已开启橙色云朵", l.Domain)
	}

	if l.Address != "" {
		if net.ParseIP(l.Address) != nil {
			add("ok", "用户连接地址是 IP %s", l.Address)
		} else if got, err := lookupV4(ctx, l.Address); err != nil {
			add("bad", "用户连接地址 %s 解析失败：%s", l.Address, shortErr(err))
		} else if len(l.IPs) == 0 {
			if isCFIP(got[0]) {
				add("ok", "用户连接地址 %s 解析到 %s", l.Address, strings.Join(got, " "))
			} else {
				add("bad", "用户连接地址 %s 解析到 %s，不是 Cloudflare 的 IP", l.Address, strings.Join(got, " "))
			}
		} else {
			want := map[string]bool{}
			for _, ip := range l.IPs {
				want[ip] = true
			}
			var extra, missing []string
			for _, ip := range got {
				if !want[ip] {
					extra = append(extra, ip)
				}
				delete(want, ip)
			}
			for ip := range want {
				missing = append(missing, ip)
			}
			sort.Strings(missing)
			switch {
			case len(extra) == 0 && len(missing) == 0:
				add("ok", "用户连接地址 %s 的 A 记录与优选 IP 一致（%d 个）", l.Address, len(got))
			case len(got) > 0 && isCFIP(got[0]) && len(got) <= 2 && len(missing) == len(l.IPs):
				add("bad", "用户连接地址 %s 解析到 %s：像是开了橙色云朵。请改成灰色云朵（仅 DNS），优选 IP 才会生效", l.Address, strings.Join(got, " "))
			default:
				if len(missing) > 0 {
					add("warn", "这些优选 IP 还没加到 %s 的 A 记录：%s", l.Address, strings.Join(missing, " "))
				}
				if len(extra) > 0 {
					add("warn", "%s 有额外的 A 记录（不在优选 IP 列表里）：%s", l.Address, strings.Join(extra, " "))
				}
			}
		}
	} else {
		add("ok", "未设置用户连接地址：客户端直接连 %s", l.Domain)
	}

	// 并发握手：落地节点（不经 Cloudflare，确认路径）+ 每个优选 IP（经 Cloudflare）
	type job struct {
		kind, target, addr, sni string
		verify                  bool
	}
	var jobs []job
	jobs = append(jobs, job{"origin", net.JoinHostPort(l.Origin, port), net.JoinHostPort(l.Origin, port), l.Domain, false})
	if len(l.IPs) == 0 {
		jobs = append(jobs, job{"dns", l.Domain, net.JoinHostPort(l.Domain, port), l.Domain, true})
	}
	for _, ip := range l.IPs {
		jobs = append(jobs, job{"ip", ip, net.JoinHostPort(ip, port), l.Domain, true})
	}
	items := make([]CDNTestItem, len(jobs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			c, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			it := wsProbe(c, j.addr, j.sni, l.Domain, l.Path, j.verify)
			it.Kind, it.Target = j.kind, j.target
			if j.kind == "origin" {
				it.Colo = ""
				if it.OK {
					it.Msg = "落地节点直连握手成功，路径正确"
				} else if strings.HasPrefix(it.Msg, "超时") {
					it.Msg = "面板连不上落地节点（落地 IP 可能只对 Cloudflare 开放，可忽略）"
				}
			}
			items[i] = it
		}()
	}
	wg.Wait()
	t.Items = items
	t.OK = true
	for _, it := range items {
		if it.Kind != "origin" && !it.OK {
			t.OK = false
		}
	}
	for _, c := range t.Checks {
		if c.Level == "bad" {
			t.OK = false
		}
	}
	return t
}

func validateCDNLine(l *CDNLine) error {
	l.Name, l.Origin, l.Domain = strings.TrimSpace(l.Name), strings.TrimSpace(l.Origin), strings.ToLower(strings.TrimSpace(l.Domain))
	l.Address, l.Path, l.Remark = strings.ToLower(strings.TrimSpace(l.Address)), strings.TrimSpace(l.Path), strings.TrimSpace(l.Remark)
	if l.Name == "" || len(l.Name) > 64 {
		return errors.New("请填写名称（不超过 64 字符）")
	}
	switch l.Protocol {
	case "trojan", "vless", "vmess":
	default:
		l.Protocol = "trojan"
	}
	if err := validHost(l.Origin); err != nil || l.Origin == "" {
		return errors.New("落地节点地址无效（填 IP 或域名）")
	}
	if !cdnPorts[l.Port] {
		return errors.New("端口必须是 Cloudflare 支持的 HTTPS 端口：443、2053、2083、2087、2096、8443")
	}
	if l.Domain == "" || validHost(l.Domain) != nil || !strings.Contains(l.Domain, ".") || net.ParseIP(l.Domain) != nil {
		return errors.New("请填写开了橙色云朵的域名")
	}
	if l.Path == "" {
		l.Path = "/"
	}
	if !strings.HasPrefix(l.Path, "/") || strings.ContainsAny(l.Path, " ?#") {
		return errors.New("WS 路径必须以 / 开头，且不能包含空格、? 或 #")
	}
	if l.Address != "" && validHost(l.Address) != nil {
		return errors.New("用户连接地址无效")
	}
	if l.Address == l.Domain {
		l.Address = ""
	}
	ips, err := parseIPList(l.IPs)
	if err != nil {
		return err
	}
	l.IPs = ips
	return nil
}

// loopCDNLines 每 10 分钟检测一次所有 CDN 线路，结果变化时记事件（失败会推送告警）。
func (a *App) loopCDNLines() {
	for {
		time.Sleep(10 * time.Minute)
		var lines []CDNLine
		a.store.View(func(st *State) {
			for _, l := range st.CDNLines {
				lines = append(lines, *l)
			}
		})
		for _, l := range lines {
			a.runCDNLineTest(l)
		}
	}
}

func (a *App) runCDNLineTest(l CDNLine) *CDNLineTest {
	t := TestCDNLine(l)
	var prev *CDNLineTest
	a.store.Update(func(st *State) error {
		for _, x := range st.CDNLines {
			if x.ID == l.ID {
				prev, x.Test = x.Test, t
			}
		}
		return nil
	})
	bad := []string{}
	for _, it := range t.Items {
		if it.Kind != "origin" && !it.OK {
			bad = append(bad, it.Target)
		}
	}
	switch {
	case !t.OK && (prev == nil || prev.OK):
		msg := fmt.Sprintf("CDN 线路「%s」检测失败", l.Name)
		if len(bad) > 0 {
			msg += "，不可用：" + strings.Join(bad, " ")
		}
		for _, c := range t.Checks {
			if c.Level == "bad" {
				msg += "；" + c.Msg
			}
		}
		a.event("warn", "%s", msg)
	case t.OK && prev != nil && !prev.OK:
		a.event("info", "CDN 线路「%s」已恢复", l.Name)
	}
	return t
}
