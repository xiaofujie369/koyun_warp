package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const udpIdle = 2 * time.Minute

type RuleRT struct {
	ID   string
	rule Rule
	dial dialer

	ln  net.Listener
	udp *net.UDPConn

	mu    sync.Mutex
	conns map[net.Conn]struct{}
	sess  map[string]*udpSession

	up, down                atomic.Int64 // 自 Agent 启动以来的累计字节（上行=客户端→目标）
	ListenErr               atomic.Value // string
	active                  atomic.Int64
	totalConns, failedConns atomic.Int64
	ProbeOK                 atomic.Bool
	probeFails              atomic.Int32
	ProbeMs                 atomic.Value // float64
	ProbeErr                atomic.Value // string
	ProbeAt                 atomic.Int64
	ProbeVia                atomic.Value // string：探测走的隧道名
	LastErr                 atomic.Value // string
	closed                  atomic.Bool
}

type udpSession struct {
	remote net.Conn
	client *net.UDPAddr
	tunnel *TunnelRT
	last   atomic.Int64
}

func validateRule(r *Rule, s Settings) error {
	if r.ListenPort < 1 || r.ListenPort > 65535 || r.TargetPort < 1 || r.TargetPort > 65535 {
		return errors.New("端口必须在 1-65535 之间")
	}
	// Cloudflare 能代理的端口不受范围限制：入口 IP 被墙时，可以让橙色云朵域名经这些端口回源到入口
	if s.PortMin > 0 && (r.ListenPort < s.PortMin || r.ListenPort > s.PortMax) && !cfProxyPorts[r.ListenPort] {
		return fmt.Errorf("监听端口需在允许范围 %d-%d 内，或使用 Cloudflare 支持的端口（%s）", s.PortMin, s.PortMax, cfProxyPortList)
	}
	if r.Target == "" || len(r.Target) > 253 {
		return errors.New("目标地址无效")
	}
	for _, c := range r.Target {
		if !(c == '.' || c == '-' || c == ':' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return errors.New("目标地址只能包含字母、数字、点、横线或 IPv6 冒号")
		}
	}
	switch r.Protocol {
	case "tcp", "udp", "both":
	default:
		return errors.New("协议必须为 tcp / udp / both")
	}
	switch r.Mode {
	case "pool", "direct":
	case "tunnel":
		if r.TunnelID == "" {
			return errors.New("固定隧道模式需要选择隧道")
		}
	case "cdn":
		if r.CDNExitID == "" {
			return errors.New("CDN 模式需要选择 CDN 出口节点")
		}
		if r.Protocol != "tcp" {
			return errors.New("CDN 模式只支持 TCP（Cloudflare CDN 不转发 UDP），协议请选 TCP")
		}
	default:
		return errors.New("出站模式无效")
	}
	if r.ListenAddr == "" {
		r.ListenAddr = "0.0.0.0"
	}
	if net.ParseIP(r.ListenAddr) == nil {
		return errors.New("监听地址必须是 IP")
	}
	if len(r.Name) > 64 || len(r.Remark) > 200 {
		return errors.New("名称或备注过长")
	}
	return nil
}

func (r *Rule) targetAddr() string {
	return net.JoinHostPort(r.Target, strconv.Itoa(r.TargetPort))
}

// applyRule 按给定配置（重新）启动规则；停用的规则只会被停止。
// 监听失败时仍保留一个已关闭的运行时记录，用于把错误上报给控制端。
func (a *Agent) applyRule(r Rule) error {
	a.stopRule(r.ID)
	rt := &RuleRT{ID: r.ID, rule: r, dial: a.dialerFor(&r), conns: map[net.Conn]struct{}{}, sess: map[string]*udpSession{}}
	rt.ProbeMs.Store(float64(-1))
	rt.ProbeErr.Store("")
	rt.ProbeVia.Store("")
	rt.LastErr.Store("")
	a.mu.Lock()
	// 保留上一轮运行的累计计数，避免编辑规则后流量归零
	if old := a.rules[r.ID]; old != nil {
		rt.up.Store(old.up.Load())
		rt.down.Store(old.down.Load())
	}
	a.rules[r.ID] = rt
	a.mu.Unlock()
	if !r.Enabled {
		rt.closed.Store(true)
		return nil
	}
	err := rt.listen(a)
	if err != nil {
		rt.closed.Store(true)
		rt.ListenErr.Store(err.Error())
		return err
	}
	go a.probeRule(rt)
	return nil
}

func (rt *RuleRT) listen(a *Agent) error {
	r := rt.rule
	laddr := net.JoinHostPort(r.ListenAddr, strconv.Itoa(r.ListenPort))
	if r.Protocol != "udp" {
		ln, err := net.Listen("tcp", laddr)
		if err != nil {
			return fmt.Errorf("监听 TCP %s 失败：%w", laddr, err)
		}
		rt.ln = ln
		go a.serveTCP(rt)
	}
	if r.Protocol != "tcp" {
		ua, _ := net.ResolveUDPAddr("udp", laddr)
		uc, err := net.ListenUDP("udp", ua)
		if err != nil {
			if rt.ln != nil {
				rt.ln.Close()
			}
			return fmt.Errorf("监听 UDP %s 失败：%w", laddr, err)
		}
		rt.udp = uc
		go a.serveUDP(rt)
		go rt.reapUDP()
	}
	return nil
}

func (a *Agent) stopRule(id string) {
	a.mu.Lock()
	rt := a.rules[id]
	a.mu.Unlock()
	if rt == nil {
		return
	}
	rt.closed.Store(true)
	if rt.ln != nil {
		rt.ln.Close()
	}
	if rt.udp != nil {
		rt.udp.Close()
	}
	rt.mu.Lock()
	for c := range rt.conns {
		c.Close()
	}
	for _, s := range rt.sess {
		s.remote.Close()
	}
	rt.mu.Unlock()
}

// removeRule 停止并彻底移除规则运行时（规则从配置中删除时调用）。
func (a *Agent) removeRule(id string) {
	a.stopRule(id)
	a.mu.Lock()
	delete(a.rules, id)
	a.mu.Unlock()
}

func (rt *RuleRT) track(c net.Conn, add bool) {
	rt.mu.Lock()
	if add {
		rt.conns[c] = struct{}{}
	} else {
		delete(rt.conns, c)
	}
	rt.mu.Unlock()
}

func (a *Agent) serveTCP(rt *RuleRT) {
	for {
		c, err := rt.ln.Accept()
		if err != nil {
			if rt.closed.Load() {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			rt.LastErr.Store(err.Error())
			time.Sleep(200 * time.Millisecond)
			continue
		}
		go a.handleTCP(rt, c)
	}
}

func (a *Agent) handleTCP(rt *RuleRT, c net.Conn) {
	defer c.Close()
	rt.totalConns.Add(1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	remote, tun, err := rt.dial(ctx, "tcp", rt.rule.targetAddr())
	cancel()
	if err != nil {
		rt.failedConns.Add(1)
		rt.LastErr.Store(time.Now().Format("15:04:05 ") + err.Error())
		return
	}
	defer remote.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
	}
	rt.track(c, true)
	rt.track(remote, true)
	rt.active.Add(1)
	if tun != nil {
		tun.Active.Add(1)
	}
	defer func() {
		rt.track(c, false)
		rt.track(remote, false)
		rt.active.Add(-1)
		if tun != nil {
			tun.Active.Add(-1)
		}
	}()
	done := make(chan struct{}, 2)
	go func() {
		pipe(remote, c, &rt.up)
		closeWrite(remote)
		done <- struct{}{}
	}()
	go func() {
		pipe(c, remote, &rt.down)
		closeWrite(c)
		done <- struct{}{}
	}()
	<-done
	// 一端结束后给另一端 30 秒排空，防止半关闭连接永久占用
	t := time.AfterFunc(30*time.Second, func() { c.Close(); remote.Close() })
	<-done
	t.Stop()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	} else {
		c.Close()
	}
}

var bufPool = sync.Pool{New: func() any { b := make([]byte, 32*1024); return &b }}

func pipe(dst io.Writer, src io.Reader, counter *atomic.Int64) {
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	buf := *bp
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			counter.Add(int64(n))
		}
		if err != nil {
			return
		}
	}
}

func (a *Agent) serveUDP(rt *RuleRT) {
	buf := make([]byte, 65535)
	for {
		n, caddr, err := rt.udp.ReadFromUDP(buf)
		if err != nil {
			if rt.closed.Load() {
				return
			}
			continue
		}
		key := caddr.String()
		rt.mu.Lock()
		s := rt.sess[key]
		rt.mu.Unlock()
		if s == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			remote, tun, err := rt.dial(ctx, "udp", rt.rule.targetAddr())
			cancel()
			if err != nil {
				rt.failedConns.Add(1)
				rt.LastErr.Store(time.Now().Format("15:04:05 ") + err.Error())
				continue
			}
			rt.totalConns.Add(1)
			s = &udpSession{remote: remote, client: caddr, tunnel: tun}
			rt.mu.Lock()
			if rt.closed.Load() {
				rt.mu.Unlock()
				remote.Close()
				return
			}
			rt.sess[key] = s
			rt.mu.Unlock()
			rt.active.Add(1)
			if tun != nil {
				tun.Active.Add(1)
			}
			go a.udpReturn(rt, key, s)
		}
		s.last.Store(time.Now().Unix())
		if _, err := s.remote.Write(buf[:n]); err == nil {
			rt.up.Add(int64(n))
		}
	}
}

func (a *Agent) udpReturn(rt *RuleRT, key string, s *udpSession) {
	defer func() {
		s.remote.Close()
		rt.mu.Lock()
		if rt.sess[key] == s {
			delete(rt.sess, key)
		}
		rt.mu.Unlock()
		rt.active.Add(-1)
		if s.tunnel != nil {
			s.tunnel.Active.Add(-1)
		}
	}()
	buf := make([]byte, 65535)
	for {
		s.remote.SetReadDeadline(time.Now().Add(udpIdle))
		n, err := s.remote.Read(buf)
		if err != nil {
			return
		}
		s.last.Store(time.Now().Unix())
		if _, err := rt.udp.WriteToUDP(buf[:n], s.client); err != nil {
			return
		}
		rt.down.Add(int64(n))
	}
}

func (rt *RuleRT) reapUDP() {
	for !rt.closed.Load() {
		time.Sleep(30 * time.Second)
		cut := time.Now().Add(-udpIdle).Unix()
		rt.mu.Lock()
		for _, s := range rt.sess {
			if s.last.Load() < cut {
				s.remote.Close()
			}
		}
		rt.mu.Unlock()
	}
}

// probeRule 通过规则自身的出站路径对目标做 TCP 连接测试。
// 纯 UDP 规则（如 Hysteria2）无法用握手判断，仅检测出站隧道是否可用。
func (a *Agent) probeRule(rt *RuleRT) {
	if rt.closed.Load() {
		return
	}
	now := time.Now().Unix()
	var ms float64 = -1
	var perr error
	via := "直连"
	if rt.rule.Mode == "cdn" {
		via = "Cloudflare CDN"
	}
	if rt.rule.Protocol == "udp" {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		c, tun, err := rt.dial(ctx, "udp", rt.rule.targetAddr())
		cancel()
		if err == nil {
			c.Close()
			if tun != nil {
				via = a.tunnelName(tun.ID)
				tun.mu.Lock()
				ms = tun.LatencyMs
				tun.mu.Unlock()
			}
		}
		perr = err
	} else {
		var tun *TunnelRT
		ms, tun, perr = tlsProbe(rt.dial, rt.rule.targetAddr())
		if tun != nil {
			via = a.tunnelName(tun.ID)
		}
	}
	prevOK := rt.ProbeOK.Load()
	first := rt.ProbeAt.Load() == 0
	rt.ProbeAt.Store(now)
	rt.ProbeVia.Store(via)
	if perr != nil {
		// 连续两次失败才判定不可达，避免单次丢包引起告警抖动
		if rt.probeFails.Add(1) >= 2 || first {
			rt.ProbeOK.Store(false)
		}
		rt.ProbeErr.Store(perr.Error())
		ms = -1
	} else {
		rt.probeFails.Store(0)
		rt.ProbeOK.Store(true)
		rt.ProbeErr.Store("")
	}
	rt.ProbeMs.Store(ms)
	if !first && prevOK != rt.ProbeOK.Load() {
		if perr != nil {
			a.event("error", "规则 %s → %s 目标不可达：%v", rt.rule.Name, rt.rule.targetAddr(), perr)
		} else {
			a.event("info", "规则 %s 目标已恢复（%.0fms）", rt.rule.Name, ms)
		}
	} else if first && perr != nil {
		a.event("warn", "规则 %s → %s 初次探测失败：%v", rt.rule.Name, rt.rule.targetAddr(), perr)
	}
}

// tlsProbe 在出站连接上发起一次 TLS 握手。WARP 边缘会代答 TCP 握手，
// 即使目标端口不存在也能"连接成功"，所以必须等到目标真正回包才算可达：
// 握手成功、TLS 告警、非 TLS 回包或对端关闭都说明目标在线，只有超时判定为不可达。
func tlsProbe(dial dialer, addr string) (float64, *TunnelRT, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c, tun, err := dial(ctx, "tcp", addr)
	if err != nil {
		return -1, tun, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(6 * time.Second))
	host, _, _ := net.SplitHostPort(addr)
	sni := "www.cloudflare.com"
	if net.ParseIP(host) == nil {
		sni = host
	}
	start := time.Now()
	err = tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: true}).HandshakeContext(ctx)
	ms := float64(time.Since(start).Microseconds()) / 1000
	if err == nil {
		return ms, tun, nil
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded) {
		return -1, tun, errors.New("目标无响应（握手超时）")
	}
	return ms, tun, nil
}

func (a *Agent) tunnelName(id string) string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if sp, ok := a.tunSpec[id]; ok {
		return sp.Name
	}
	return id
}

func (rt *RuleRT) Snapshot() map[string]any {
	ms, _ := rt.ProbeMs.Load().(float64)
	le, _ := rt.ListenErr.Load().(string)
	return map[string]any{
		"id":           rt.ID,
		"up":           rt.up.Load(),
		"down":         rt.down.Load(),
		"listen_err":   le,
		"running":      !rt.closed.Load(),
		"active":       rt.active.Load(),
		"total_conns":  rt.totalConns.Load(),
		"failed_conns": rt.failedConns.Load(),
		"probe_ok":     rt.ProbeOK.Load(),
		"probe_ms":     ms,
		"probe_err":    rt.ProbeErr.Load(),
		"probe_at":     rt.ProbeAt.Load(),
		"probe_via":    rt.ProbeVia.Load(),
		"last_err":     rt.LastErr.Load(),
	}
}
