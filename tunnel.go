package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// reservedBind 在每个出站 WireGuard 报文的保留字节写入 Cloudflare client_id，
// 并在入站方向清零，否则 wireguard-go 会把报文类型识别错误而丢弃。
type reservedBind struct {
	conn.Bind
	r [3]byte
}

func (b *reservedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, p, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	out := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		fn := fn
		out[i] = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, err := fn(packets, sizes, eps)
			for j := 0; j < n; j++ {
				if sizes[j] >= 4 {
					packets[j][1], packets[j][2], packets[j][3] = 0, 0, 0
				}
			}
			return n, err
		}
	}
	return out, p, nil
}

func (b *reservedBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	for _, buf := range bufs {
		if len(buf) >= 4 {
			buf[1], buf[2], buf[3] = b.r[0], b.r[1], b.r[2]
		}
	}
	return b.Bind.Send(bufs, ep)
}

// TunnelRT 是一条运行中的 WARP 隧道。
type TunnelRT struct {
	ID       string
	dev      *device.Device
	tnet     *netstack.Net
	endpoint string // 实际使用的 ip:port

	mu            sync.Mutex
	Status        string // starting | up | degraded | down | disabled
	LatencyMs     float64
	Fails         int
	LastProbe     int64
	LastOK        int64
	LastHandshake int64
	Rx, Tx        int64
	EgressIP      string
	Colo          string
	WarpMode      string // on | plus
	TraceAt       int64
	Err           string
	Started       int64

	Active atomic.Int64 // 经过此隧道的活跃连接
}

func resolveEndpoint(ep string) (string, error) {
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		return "", fmt.Errorf("端点格式错误 %q: %w", ep, err)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(ip, mustPort(port)).String(), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("解析端点 %s 失败: %v", host, err)
	}
	return netip.AddrPortFrom(ips[0], mustPort(port)).String(), nil
}

func mustPort(s string) uint16 {
	p, _ := strconv.Atoi(s)
	return uint16(p)
}

func b64ToHex(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func StartTunnel(t *Tunnel, endpoint string, mtu int) (*TunnelRT, error) {
	ep, err := resolveEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	for _, a := range []string{t.AddressV4, t.AddressV6} {
		if a == "" {
			continue
		}
		if p, err := netip.ParsePrefix(a); err == nil {
			addrs = append(addrs, p.Addr())
		} else if ip, err := netip.ParseAddr(a); err == nil {
			addrs = append(addrs, ip)
		}
	}
	dns := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1")}
	tdev, tnet, err := netstack.CreateNetTUN(addrs, dns, mtu)
	if err != nil {
		return nil, err
	}
	bind := &reservedBind{Bind: conn.NewDefaultBind()}
	if cid, err := base64.StdEncoding.DecodeString(t.ClientID); err == nil && len(cid) >= 3 {
		copy(bind.r[:], cid[:3])
	}
	logger := device.NewLogger(device.LogLevelSilent, "")
	dev := device.NewDevice(tdev, bind, logger)
	priv, err := b64ToHex(t.PrivateKey)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("私钥无效: %w", err)
	}
	pub, err := b64ToHex(t.PeerPublic)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("对端公钥无效: %w", err)
	}
	cfg := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\npersistent_keepalive_interval=25\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n", priv, pub, ep)
	if err := dev.IpcSet(cfg); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	return &TunnelRT{ID: t.ID, dev: dev, tnet: tnet, endpoint: ep, Status: "starting", Started: time.Now().Unix()}, nil
}

func (r *TunnelRT) Close() {
	if r.dev != nil {
		r.dev.Close()
	}
}

func (r *TunnelRT) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return r.tnet.DialContext(ctx, network, addr)
}

// readStats 从 wireguard-go 的 UAPI 读取握手时间与收发字节。
func (r *TunnelRT) readStats() {
	s, err := r.dev.IpcGet()
	if err != nil {
		return
	}
	var hs, rx, tx int64
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(v, 10, 64)
		switch k {
		case "last_handshake_time_sec":
			hs = n
		case "rx_bytes":
			rx += n
		case "tx_bytes":
			tx += n
		}
	}
	r.mu.Lock()
	r.LastHandshake, r.Rx, r.Tx = hs, rx, tx
	r.mu.Unlock()
}

// probe 通过隧道向 1.1.1.1:443 建立 TCP 连接测量延迟。
func (r *TunnelRT) probe(timeout time.Duration) (float64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	c, err := r.tnet.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("1.1.1.1:443"))
	if err != nil {
		return 0, err
	}
	c.Close()
	return float64(time.Since(start).Microseconds()) / 1000, nil
}

// trace 访问 Cloudflare trace 接口获取出口 IP、机房以及 WARP 状态。
func (r *TunnelRT) trace() (map[string]string, error) {
	tr := &http.Transport{
		DialContext:     r.tnet.DialContext,
		TLSClientConfig: &tls.Config{ServerName: "one.one.one.one"},
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	resp, err := cl.Get("https://1.1.1.1/cdn-cgi/trace")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode != 200 {
		return nil, errors.New(resp.Status)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			out[k] = v
		}
	}
	return out, nil
}

func (r *TunnelRT) Snapshot() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return map[string]any{
		"status":         r.Status,
		"latency_ms":     r.LatencyMs,
		"fails":          r.Fails,
		"last_probe":     r.LastProbe,
		"last_ok":        r.LastOK,
		"last_handshake": r.LastHandshake,
		"rx":             r.Rx,
		"tx":             r.Tx,
		"egress_ip":      r.EgressIP,
		"colo":           r.Colo,
		"warp":           r.WarpMode,
		"endpoint":       r.endpoint,
		"error":          r.Err,
		"started":        r.Started,
		"active":         r.Active.Load(),
	}
}
