package main

import (
	"context"
	"errors"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	cdnIPCooldown = 60 * time.Second // 某个优选 IP 失败后暂停使用的时间，连续失败时翻倍
	cdnIPMaxCool  = 10 * time.Minute
	cdnMaxTries   = 3                // 一条连接最多换几个 IP 重试
	cdnMaxIPs     = 20
)

// errCDNExit 表示请求已经到达 CDN 出口、是出口给出的结果（例如连不上目标），
// 换一个 Cloudflare IP 也不会更好，所以不算 IP 的失败、也不重试。
type errCDNExit struct{ error }

func (e errCDNExit) Unwrap() error { return e.error }

type cdnIPState struct {
	ok, fail  atomic.Int64
	streak    atomic.Int64 // 连续失败次数
	lastMs    atomic.Int64
	coolUntil atomic.Int64 // unix 毫秒
	lastErr   atomic.Value // string
}

// cdnIPPool 按轮询在多个优选 IP 间分配新连接，失败的 IP 暂停一段时间。
type cdnIPPool struct {
	mu sync.Mutex
	ip map[string]*cdnIPState
	rr atomic.Uint64
}

func newCDNIPPool() *cdnIPPool { return &cdnIPPool{ip: map[string]*cdnIPState{}} }

func (p *cdnIPPool) state(ip string) *cdnIPState {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.ip[ip]
	if s == nil {
		s = &cdnIPState{}
		s.lastErr.Store("")
		p.ip[ip] = s
	}
	return s
}

// order 返回本次尝试的 IP 顺序：从轮询位置开始，可用的在前，暂停中的按恢复时间排在后面。
func (p *cdnIPPool) order(ips []string) []string {
	n := len(ips)
	start := int(p.rr.Add(1)-1) % n
	now := time.Now().UnixMilli()
	var ready, cooling []string
	for i := 0; i < n; i++ {
		ip := ips[(start+i)%n]
		if p.state(ip).coolUntil.Load() > now {
			cooling = append(cooling, ip)
		} else {
			ready = append(ready, ip)
		}
	}
	sort.SliceStable(cooling, func(i, j int) bool {
		return p.state(cooling[i]).coolUntil.Load() < p.state(cooling[j]).coolUntil.Load()
	})
	return append(ready, cooling...)
}

// dial 经多个优选 IP 建立 CDN 连接；没有优选 IP 时按域名解析。
func (p *cdnIPPool) dial(ctx context.Context, rt CDNRoute, target string) (net.Conn, error) {
	ips := rt.ConnectIPs
	if len(ips) == 0 && rt.ConnectIP != "" {
		ips = []string{rt.ConnectIP}
	}
	if len(ips) == 0 {
		return cdnDial(ctx, rt.URL, "", target)
	}
	var lastErr error
	for i, ip := range p.order(ips) {
		if i >= cdnMaxTries || ctx.Err() != nil {
			break
		}
		s := p.state(ip)
		start := time.Now()
		// 还有其它 IP 可换时，单个 IP 最多等 4 秒，避免一个坏 IP 耗光整条连接的超时
		tctx, cancel := ctx, context.CancelFunc(func() {})
		if i < len(ips)-1 && i < cdnMaxTries-1 {
			tctx, cancel = context.WithTimeout(ctx, 4*time.Second)
		}
		c, err := cdnDial(tctx, rt.URL, ip, target)
		cancel()
		if err == nil {
			s.ok.Add(1)
			s.lastMs.Store(time.Since(start).Milliseconds())
			s.coolUntil.Store(0)
			s.streak.Store(0)
			return c, nil
		}
		var ee errCDNExit
		if errors.As(err, &ee) {
			s.ok.Add(1) // IP 本身是通的
			return nil, err
		}
		s.fail.Add(1)
		cool := cdnIPCooldown << min(s.streak.Add(1)-1, 4)
		s.coolUntil.Store(time.Now().Add(min(cool, cdnIPMaxCool)).UnixMilli())
		s.lastErr.Store(time.Now().Format("15:04:05 ") + err.Error())
		lastErr = err
	}
	if lastErr == nil {
		lastErr = ctx.Err()
	}
	return nil, lastErr
}

// snapshot 只返回当前配置里还在用的 IP。
func (p *cdnIPPool) snapshot(inUse map[string]bool) map[string]any {
	now := time.Now().UnixMilli()
	out := map[string]any{}
	p.mu.Lock()
	defer p.mu.Unlock()
	for ip, s := range p.ip {
		if !inUse[ip] {
			delete(p.ip, ip)
			continue
		}
		le, _ := s.lastErr.Load().(string)
		out[ip] = map[string]any{"ok": s.ok.Load(), "fail": s.fail.Load(), "ms": s.lastMs.Load(),
			"cooling": s.coolUntil.Load() > now, "error": le}
	}
	return out
}
