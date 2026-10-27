package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

// Cloudflare 代理 HTTPS 时支持的源站端口。
var cdnPorts = map[int]bool{443: true, 2053: true, 2083: true, 2087: true, 2096: true, 8443: true}

// Cloudflare 代理时允许的全部源站端口（HTTPS 与 HTTP），转发规则的监听端口可以使用它们。
var cfProxyPorts = map[int]bool{443: true, 2053: true, 2083: true, 2087: true, 2096: true, 8443: true,
	80: true, 8080: true, 8880: true, 2052: true, 2082: true, 2086: true, 2095: true}

const cfProxyPortList = "HTTPS 443/2053/2083/2087/2096/8443，HTTP 80/8080/8880/2052/2082/2086/2095"

const cdnPathPrefix = "/kw-cdn/"

// CDNExitCfg 是下发给 CDN 出口节点的配置。
type CDNExitCfg struct {
	Port    int      `json:"port"`
	Secret  string   `json:"secret"`
	Domain  string   `json:"domain"`
	Allowed []string `json:"allowed"` // 允许连接的目标 host:port，防止被当作开放代理
	Cert    string   `json:"cert"`    // 可选：Cloudflare 源服务器证书等受信任证书
	Key     string   `json:"key"`
}

// CDNRoute 是入口节点经某个 CDN 出口转发时使用的地址。
type CDNRoute struct {
	URL        string   `json:"url"`         // wss://域名:端口/kw-cdn/密钥
	ConnectIP  string   `json:"connect_ip"`  // 第一个优选 IP，兼容 2.1.3 及更早的 Agent
	ConnectIPs []string `json:"connect_ips"` // 可选：多个 Cloudflare 优选 IP，轮询使用；留空按 DNS 解析
}

// ---------- 出口：在 Cloudflare 支持的端口上接受 WebSocket，再去连目标 ----------

type CDNExit struct {
	cfg     CDNExitCfg
	ln      net.Listener
	srv     *http.Server
	allowed atomic.Value // map[string]bool
	closed  atomic.Bool

	active, total, failed atomic.Int64
	up, down              atomic.Int64
	lastErr               atomic.Value // string
}

// chanListener 把预先识别好（TLS / 明文）的连接交给 http.Server。
type chanListener struct {
	ch    chan net.Conn
	addr  net.Addr
	once  sync.Once
	close chan struct{}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.close:
		return nil, net.ErrClosed
	}
}
func (l *chanListener) Close() error   { l.once.Do(func() { close(l.close) }); return nil }
func (l *chanListener) Addr() net.Addr { return l.addr }

// peekConn 让已经读出首字节的连接还能被后续的 TLS / HTTP 读到。
type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func selfSignedCert(domain string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	sn, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// StartCDNExit 在同一个端口上同时接受 TLS 和明文 HTTP：Cloudflare 的 SSL 模式为
// 「完全」时用 TLS 回源（自签证书即可），为「灵活」时用明文回源，两种都能工作。
func StartCDNExit(cfg CDNExitCfg) (*CDNExit, error) {
	var cert tls.Certificate
	var err error
	if cfg.Cert != "" {
		cert, err = tls.X509KeyPair([]byte(cfg.Cert), []byte(cfg.Key))
		if err != nil {
			return nil, fmt.Errorf("CDN 出口证书无效：%w", err)
		}
	} else if cert, err = selfSignedCert(cfg.Domain); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(cfg.Port))
	if err != nil {
		return nil, fmt.Errorf("CDN 出口监听 %d 失败：%w", cfg.Port, err)
	}
	e := &CDNExit{cfg: cfg, ln: ln}
	e.SetAllowed(cfg.Allowed)
	e.lastErr.Store("")
	cl := &chanListener{ch: make(chan net.Conn), addr: ln.Addr(), close: make(chan struct{})}
	// 不设置 ALPN：Cloudflare 回源可能只提供 h2，设了 http/1.1 会直接握手失败；不协商时双方回落到 HTTP/1.1
	tcfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	e.srv = &http.Server{Handler: http.HandlerFunc(e.serve), ReadHeaderTimeout: 10 * time.Second}
	go e.srv.Serve(cl)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if e.closed.Load() {
					cl.Close()
					return
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}
			go func(c net.Conn) {
				c.SetReadDeadline(time.Now().Add(10 * time.Second))
				br := bufio.NewReader(c)
				b, err := br.Peek(1)
				c.SetReadDeadline(time.Time{})
				if err != nil {
					c.Close()
					return
				}
				var out net.Conn = &peekConn{Conn: c, r: br}
				if b[0] == 0x16 { // TLS ClientHello
					out = tls.Server(out, tcfg)
				}
				select {
				case cl.ch <- out:
				case <-cl.close:
					c.Close()
				}
			}(c)
		}
	}()
	return e, nil
}

func (e *CDNExit) SetAllowed(list []string) {
	m := make(map[string]bool, len(list))
	for _, t := range list {
		m[t] = true
	}
	e.allowed.Store(m)
}

func (e *CDNExit) Close() {
	e.closed.Store(true)
	e.ln.Close()
	e.srv.Close()
}

func (e *CDNExit) serve(w http.ResponseWriter, r *http.Request) {
	// 非本系统的请求一律返回普通 404，看起来就是一个空网站
	if r.URL.Path != cdnPathPrefix+e.cfg.Secret || !websocketUpgrade(r) {
		http.NotFound(w, r)
		return
	}
	target := r.Header.Get("X-KW-Target")
	if m, _ := e.allowed.Load().(map[string]bool); !m[target] {
		e.failed.Add(1)
		e.lastErr.Store(time.Now().Format("15:04:05 ") + "拒绝未授权的目标 " + target)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	e.total.Add(1)
	remote, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		e.failed.Add(1)
		e.lastErr.Store(time.Now().Format("15:04:05 ") + err.Error())
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer remote.Close()
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		e.failed.Add(1)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nc := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	defer nc.Close()
	e.active.Add(1)
	defer e.active.Add(-1)
	done := make(chan struct{}, 2)
	go func() { pipe(remote, nc, &e.up); closeWrite(remote); done <- struct{}{} }()
	go func() { pipe(nc, remote, &e.down); nc.Close(); done <- struct{}{} }()
	<-done
	t := time.AfterFunc(30*time.Second, func() { nc.Close(); remote.Close() })
	<-done
	t.Stop()
}

func websocketUpgrade(r *http.Request) bool {
	return r.Header.Get("Upgrade") != "" && r.Header.Get("Sec-WebSocket-Key") != ""
}

func (e *CDNExit) Snapshot() map[string]any {
	le, _ := e.lastErr.Load().(string)
	m, _ := e.allowed.Load().(map[string]bool)
	return map[string]any{
		"listening": !e.closed.Load(), "port": e.cfg.Port, "domain": e.cfg.Domain, "allowed": len(m),
		"active": e.active.Load(), "total": e.total.Load(), "failed": e.failed.Load(),
		"up": e.up.Load(), "down": e.down.Load(), "error": le,
	}
}

// ---------- 入口：把一条 TCP 连接封装成 WSS 发往 Cloudflare ----------

func cdnDial(ctx context.Context, wsURL, connectIP, target string) (net.Conn, error) {
	u, err := url.Parse(wsURL)
	if err != nil {
		return nil, err
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	var d net.Dialer
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{ServerName: host, NextProtos: []string{"http/1.1"}},
		ForceAttemptHTTP2: false,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if connectIP != "" {
				addr = net.JoinHostPort(connectIP, port)
			}
			return d.DialContext(ctx, network, addr)
		},
	}
	ws, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPClient:      &http.Client{Transport: tr},
		HTTPHeader:      http.Header{"X-KW-Target": {target}, "User-Agent": {"Mozilla/5.0"}},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		if resp != nil {
			switch resp.StatusCode {
			case 403:
				return nil, errors.New("CDN 出口拒绝了该目标（出口配置尚未同步）")
			case 404:
				return nil, errors.New("CDN 出口返回 404：密钥不匹配，或域名没有指向出口节点")
			case 502:
				return nil, errCDNExit{errors.New("CDN 出口连不上目标")}
			case 521, 522, 523:
				return nil, fmt.Errorf("Cloudflare %d：连不上出口源站，检查出口端口与防火墙", resp.StatusCode)
			case 525, 526:
				return nil, fmt.Errorf("Cloudflare %d：回源证书不被信任。SSL 模式为「完全（严格）」时，请在出口节点设置里填入 Cloudflare 源服务器证书", resp.StatusCode)
			}
			return nil, fmt.Errorf("CDN 握手失败：HTTP %d", resp.StatusCode)
		}
		return nil, err
	}
	// 拨号用的 ctx 只管握手；连接本身的生命周期不能跟着它结束
	return websocket.NetConn(context.Background(), ws, websocket.MessageBinary), nil
}
