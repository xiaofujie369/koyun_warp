package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const offlineAfter = 30 // 秒：超过这么久没同步视为离线

// App 是控制端：保存全部配置、调用 WARP 接口，并汇总各节点 Agent 上报的状态。
type App struct {
	store   *Store
	metrics *Metrics

	mu    sync.RWMutex
	nodes map[string]*NodeRT

	tunnelOps sync.Map // tunnelID -> *sync.Mutex，串行化同一隧道的换密钥/重新注册
}

// NodeRT 是某个节点最近一次上报的内存状态。
type NodeRT struct {
	LastSeen int64
	IP       string
	Report   AgentReport
	Online   bool
	tunnels  map[string]map[string]any
	rules    map[string]map[string]any
	prevT    time.Time
	prevUp   map[string][2]int64 // ruleID -> 上次上报的累计 up/down
	prevTun  map[string][2]int64
	prevBoot string
	pending  map[string][2]int64 // 尚未写回状态文件的流量增量
}

func NewApp(store *Store) *App {
	return &App{store: store, metrics: NewMetrics(), nodes: map[string]*NodeRT{}}
}

func (a *App) settings() Settings {
	var s Settings
	a.store.View(func(st *State) { s = st.Settings })
	return s
}

func (a *App) event(level, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("[%s] %s", level, msg)
	a.store.AddEvent(level, msg)
	if level != "info" {
		go a.notify(msg)
	}
}

func (a *App) notify(msg string) {
	s := a.settings()
	if s.TelegramToken == "" || s.TelegramChat == "" {
		return
	}
	cl := &http.Client{Timeout: 10 * time.Second}
	resp, err := cl.PostForm("https://api.telegram.org/bot"+s.TelegramToken+"/sendMessage", url.Values{
		"chat_id": {s.TelegramChat},
		"text":    {"[Koyun WARP] " + msg},
	})
	if err == nil {
		resp.Body.Close()
	}
}

func (a *App) tunnelLock(id string) *sync.Mutex {
	m, _ := a.tunnelOps.LoadOrStore(id, &sync.Mutex{})
	return m.(*sync.Mutex)
}

func (a *App) nodeRT(id string) *NodeRT {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.nodes[id]
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// ---------- 节点 ----------

func (a *App) CreateNode(name, host, remark string) (*Node, error) {
	n := &Node{ID: newID("n_"), Name: name, PublicHost: host, Remark: remark, CreatedAt: time.Now().Unix(), Version: 1}
	n.InstallToken, n.InstallExpires = "kwi_"+randHex(16), time.Now().Add(30*time.Minute).Unix()
	err := a.store.Update(func(st *State) error {
		st.Nodes = append(st.Nodes, n)
		return nil
	})
	if err == nil {
		a.event("info", "已创建节点 %s", name)
	}
	return n, err
}

func (a *App) RegenInstall(id string) (*Node, error) {
	var out Node
	err := a.store.Update(func(st *State) error {
		n := st.node(id)
		if n == nil {
			return errors.New("节点不存在")
		}
		n.InstallToken, n.InstallExpires = "kwi_"+randHex(16), time.Now().Add(30*time.Minute).Unix()
		out = *n
		return nil
	})
	return &out, err
}

// IssueAgentToken 在 Agent 首次启动注册时调用：校验短期安装凭证并签发新的永久 Agent 令牌。
// 只有真正运行起来的 Agent 才会换取令牌；安装链接被预览或重复下载不会影响已装好的节点。
// 同一节点再次注册（重装）会轮换令牌，旧令牌随即失效。
func (a *App) IssueAgentToken(installToken string) (*Node, string, error) {
	var out Node
	tok := "kwa_" + randHex(32)
	err := a.store.Update(func(st *State) error {
		for _, n := range st.Nodes {
			if n.InstallToken != "" && n.InstallToken == installToken {
				if time.Now().Unix() > n.InstallExpires {
					return errors.New("安装命令已过期，请在面板重新生成")
				}
				n.TokenHash = hashToken(tok)
				out = *n
				return nil
			}
		}
		return errors.New("安装凭证无效")
	})
	if err != nil {
		return nil, "", err
	}
	a.event("info", "节点 %s 的 Agent 已注册", out.Name)
	return &out, tok, nil
}

// nodeByInstall 按有效的安装凭证查找节点，只读，用于生成安装脚本。
func (a *App) nodeByInstall(installToken string) (Node, error) {
	var out Node
	err := errors.New("安装凭证无效，请在面板重新生成安装命令")
	a.store.View(func(st *State) {
		for _, n := range st.Nodes {
			if n.InstallToken != "" && n.InstallToken == installToken {
				if time.Now().Unix() > n.InstallExpires {
					err = errors.New("安装命令已过期，请在面板重新生成")
					return
				}
				out, err = *n, nil
			}
		}
	})
	return out, err
}

func (a *App) checkInstall(installToken string) bool {
	ok := false
	a.store.View(func(st *State) {
		for _, n := range st.Nodes {
			if n.InstallToken != "" && n.InstallToken == installToken && time.Now().Unix() <= n.InstallExpires {
				ok = true
			}
		}
	})
	return ok
}

func (a *App) nodeByToken(tok string) (Node, bool) {
	h := hashToken(tok)
	var out Node
	found := false
	a.store.View(func(st *State) {
		for _, n := range st.Nodes {
			if n.TokenHash != "" && n.TokenHash == h {
				out, found = *n, true
			}
		}
	})
	return out, found
}

// DeleteNode 删除节点以及其上的全部隧道（注销远端 WARP 设备）和规则。
func (a *App) DeleteNode(id string) error {
	var tids []string
	var name string
	a.store.View(func(st *State) {
		if n := st.node(id); n != nil {
			name = n.Name
		}
		for _, t := range st.Tunnels {
			if t.NodeID == id {
				tids = append(tids, t.ID)
			}
		}
	})
	if name == "" {
		return errors.New("节点不存在")
	}
	var blocked string
	a.store.View(func(st *State) {
		for _, r := range st.Rules {
			if r.Mode == "cdn" && r.CDNExitID == id && r.NodeID != id {
				blocked = r.Name
			}
		}
	})
	if blocked != "" {
		return fmt.Errorf("规则「%s」经此节点走 CDN，请先修改该规则", blocked)
	}
	err := a.store.Update(func(st *State) error {
		var keep []*Rule
		for _, r := range st.Rules {
			if r.NodeID != id {
				keep = append(keep, r)
			} else {
				a.metrics.Drop("rule:" + r.ID)
			}
		}
		st.Rules = keep
		return nil
	})
	if err != nil {
		return err
	}
	for _, tid := range tids {
		if err := a.DeleteTunnel(tid); err != nil {
			log.Printf("删除隧道 %s: %v", tid, err)
		}
	}
	a.mu.Lock()
	delete(a.nodes, id)
	a.mu.Unlock()
	a.metrics.Drop("node:" + id)
	a.event("info", "已删除节点 %s", name)
	return a.store.Update(func(st *State) error {
		for i, n := range st.Nodes {
			if n.ID == id {
				st.Nodes = append(st.Nodes[:i], st.Nodes[i+1:]...)
				break
			}
		}
		return nil
	})
}

// BuildConfig 组装下发给节点的期望配置。
func (a *App) BuildConfig(nodeID string) *AgentConfig {
	var cfg *AgentConfig
	a.store.View(func(st *State) {
		n := st.node(nodeID)
		if n == nil {
			return
		}
		s := st.Settings
		cfg = &AgentConfig{Version: n.Version, NodeID: n.ID, NodeName: n.Name, MTU: s.MTU, ProbeInterval: s.ProbeInterval,
			FailThreshold: s.FailThreshold, PoolStrategy: s.PoolStrategy, DefaultEndpoint: s.DefaultEndpoint,
			Tunnels: []TunnelSpec{}, Rules: []Rule{}}
		for _, t := range st.Tunnels {
			if t.NodeID != nodeID || !t.Enabled {
				continue
			}
			cfg.Tunnels = append(cfg.Tunnels, TunnelSpec{ID: t.ID, Name: t.Name, PrivateKey: t.PrivateKey, PeerPublic: t.PeerPublic,
				AddressV4: t.AddressV4, AddressV6: t.AddressV6, ClientID: t.ClientID, Endpoint: t.Endpoint,
				RestartSeq: t.RestartSeq, ProbeSeq: t.ProbeSeq})
		}
		cfg.CDNRoutes = map[string]CDNRoute{}
		for _, r := range st.Rules {
			if r.NodeID != nodeID {
				continue
			}
			c := *r
			c.TotalUp, c.TotalDown = 0, 0
			cfg.Rules = append(cfg.Rules, c)
			if r.Mode == "cdn" {
				if ex := st.node(r.CDNExitID); ex != nil && ex.CDNEnabled {
					ips := ex.CDNConnectIPs
					if len(n.CDNPreferIPs) > 0 {
						ips = n.CDNPreferIPs // 入口自己的优选 IP 优先：不同地区的入口适合的 Cloudflare IP 不同
					}
					rt := CDNRoute{URL: cdnURL(ex), ConnectIPs: ips}
					if len(ips) > 0 {
						rt.ConnectIP = ips[0]
					}
					cfg.CDNRoutes[ex.ID] = rt
				}
			}
		}
		if n.CDNEnabled {
			ex := &CDNExitCfg{Port: n.CDNPort, Secret: n.CDNSecret, Domain: n.CDNDomain, Cert: n.CDNCert, Key: n.CDNKey, Allowed: []string{}}
			for _, r := range st.Rules {
				if r.Mode == "cdn" && r.CDNExitID == n.ID && r.Enabled {
					ex.Allowed = append(ex.Allowed, r.targetAddr())
				}
			}
			cfg.CDNExit = ex
		}
	})
	return cfg
}

func cdnURL(n *Node) string {
	host := n.CDNDomain
	if n.CDNPort != 443 {
		host = net.JoinHostPort(n.CDNDomain, strconv.Itoa(n.CDNPort))
	}
	return "wss://" + host + cdnPathPrefix + n.CDNSecret
}

// HandleReport 处理一次 Agent 同步：更新在线状态、累计流量、写监控序列、转存事件。
func (a *App) HandleReport(n Node, ip string, rep AgentReport) {
	now := time.Now()
	ts := now.Unix()
	a.mu.Lock()
	rt := a.nodes[n.ID]
	if rt == nil {
		rt = &NodeRT{prevUp: map[string][2]int64{}, prevTun: map[string][2]int64{}, pending: map[string][2]int64{}}
		a.nodes[n.ID] = rt
	}
	wasOnline, seenBefore := rt.Online, rt.prevBoot != ""
	sameBoot := rt.prevBoot == rep.Boot
	dt := now.Sub(rt.prevT).Seconds()
	if !sameBoot || dt <= 0 || dt > 120 {
		dt = 0
	}
	rt.LastSeen, rt.IP, rt.Report, rt.Online = ts, ip, rep, true
	rt.tunnels = map[string]map[string]any{}
	for _, t := range rep.Tunnels {
		if id, _ := t["id"].(string); id != "" {
			rt.tunnels[id] = t
		}
	}
	rt.rules = map[string]map[string]any{}
	var fwdUp, fwdDown, conns float64
	for _, r := range rep.Rules {
		id, _ := r["id"].(string)
		if id == "" {
			continue
		}
		rt.rules[id] = r
		up, down := int64(num(r["up"])), int64(num(r["down"]))
		prev, had := rt.prevUp[id]
		if !sameBoot || up < prev[0] || down < prev[1] {
			// Agent 重启后计数从 0 开始：本次上报的值全部是新增流量
			prev, had = [2]int64{0, 0}, true
		}
		if !had {
			// 控制端重启后第一次见到该规则：以当前值为基线，避免重复累计
			prev = [2]int64{up, down}
		}
		du, dd := up-prev[0], down-prev[1]
		rt.prevUp[id] = [2]int64{up, down}
		p := rt.pending[id]
		rt.pending[id] = [2]int64{p[0] + du, p[1] + dd}
		vals := map[string]float64{"conns": num(r["active"]), "latency": num(r["probe_ms"])}
		if ok, _ := r["running"].(bool); !ok {
			vals["latency"] = -1
		}
		if dt > 0 {
			vals["up"], vals["down"] = float64(du)/dt, float64(dd)/dt
			fwdUp += vals["up"]
			fwdDown += vals["down"]
		}
		conns += num(r["active"])
		a.metrics.Push("rule:"+id, ts, vals)
	}
	for id, t := range rt.tunnels {
		rx, tx := int64(num(t["rx"])), int64(num(t["tx"]))
		vals := map[string]float64{"conns": num(t["active"])}
		if st, _ := t["status"].(string); st == "up" || st == "degraded" {
			vals["latency"] = num(t["latency_ms"])
		} else {
			vals["latency"] = -1
		}
		if p, ok := rt.prevTun[id]; ok && dt > 0 && rx >= p[0] && tx >= p[1] {
			vals["rx"], vals["tx"] = float64(rx-p[0])/dt, float64(tx-p[1])/dt
		}
		rt.prevTun[id] = [2]int64{rx, tx}
		a.metrics.Push("tunnel:"+id, ts, vals)
	}
	rt.prevT, rt.prevBoot = now, rep.Boot
	if rep.CDN != nil {
		a.metrics.Push("cdn:"+n.ID, ts, map[string]float64{"conns": num(rep.CDN["active"])})
	}
	a.mu.Unlock()

	nv := map[string]float64{"cpu": rep.Sys.CPU, "mem": float64(rep.Sys.MemUsed), "rx": rep.Sys.RxRate, "tx": rep.Sys.TxRate, "conns": conns}
	if dt > 0 {
		nv["fwd_up"], nv["fwd_down"] = fwdUp, fwdDown
	}
	a.metrics.Push("node:"+n.ID, ts, nv)

	if n.FirstSeen == 0 {
		a.store.Update(func(st *State) error {
			if p := st.node(n.ID); p != nil && p.FirstSeen == 0 {
				p.FirstSeen = ts
				p.InstallToken = "" // 安装完成后作废安装凭证
			}
			return nil
		})
		a.event("info", "节点 %s 已上线（%s，%s/%s，Agent %s）", n.Name, ip, rep.OS, rep.Arch, rep.Version)
	} else if !wasOnline && seenBefore {
		a.event("info", "节点 %s 已恢复在线（%s）", n.Name, ip)
	}
	for _, e := range rep.Events {
		msg := fmt.Sprintf("[%s] %s", n.Name, e.Message)
		a.store.AddEvent(e.Level, msg)
		if e.Level != "info" {
			go a.notify(msg)
		}
	}
}

func num(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int64:
		return float64(x)
	case int:
		return float64(x)
	}
	return 0
}

// ---------- WARP 账户 ----------

// CreateTunnel 为节点注册新的 WARP 设备，可选从密钥池绑定 WARP+。
// keyID: "" 不绑定，"auto" 自动选取空闲密钥，其它为指定密钥。
func (a *App) CreateTunnel(nodeID, name, endpoint, keyID string) (*Tunnel, error) {
	ok := false
	a.store.View(func(st *State) { ok = st.node(nodeID) != nil })
	if !ok {
		return nil, errors.New("请先选择节点")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	t, err := warpRegister(ctx)
	if err != nil {
		return nil, err
	}
	t.ID = newID("t_")
	t.NodeID = nodeID
	t.Name = name
	t.Endpoint = endpoint
	t.Enabled = true
	if t.Name == "" {
		t.Name = "WARP-" + t.ID[2:6]
	}
	if err := a.store.Update(func(st *State) error {
		st.Tunnels = append(st.Tunnels, t)
		st.bump(nodeID)
		return nil
	}); err != nil {
		return nil, err
	}
	a.event("info", "已注册 WARP 设备 %s（%s）", t.Name, t.AddressV4)
	if keyID != "" {
		if err := a.RotateKey(t.ID, keyID); err != nil {
			a.event("warn", "%s 绑定密钥失败，以免费 WARP 运行：%v", t.Name, err)
		}
	}
	return t, nil
}

func (a *App) DeleteTunnel(id string) error {
	l := a.tunnelLock(id)
	l.Lock()
	defer l.Unlock()
	var t Tunnel
	inUse := ""
	a.store.View(func(st *State) {
		if p := st.tunnel(id); p != nil {
			t = *p
		}
		for _, r := range st.Rules {
			if r.Mode == "tunnel" && r.TunnelID == id {
				inUse = r.Name
			}
		}
	})
	if t.ID == "" {
		return errors.New("隧道不存在")
	}
	if inUse != "" {
		return fmt.Errorf("规则「%s」固定使用该隧道，请先修改规则", inUse)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := warpDeleteDevice(ctx, &t); err != nil {
		log.Printf("删除远端设备失败（忽略）: %v", err)
	}
	a.metrics.Drop("tunnel:" + id)
	a.event("info", "已删除隧道 %s", t.Name)
	return a.store.Update(func(st *State) error {
		for i, p := range st.Tunnels {
			if p.ID == id {
				st.Tunnels = append(st.Tunnels[:i], st.Tunnels[i+1:]...)
				break
			}
		}
		for _, k := range st.Keys {
			if k.TunnelID == id {
				k.TunnelID, k.Status = "", "idle"
			}
		}
		st.bump(t.NodeID)
		return nil
	})
}

// RotateKey 为隧道更换 WARP+ 密钥。keyID 为 "auto" 时按顺序尝试空闲密钥，
// 失败的密钥会标记为 invalid。keyID 为 "none" 时释放当前密钥。
// 成功后递增 RestartSeq，让 Agent 重新握手使新许可证生效。
func (a *App) RotateKey(tunnelID, keyID string) error {
	l := a.tunnelLock(tunnelID)
	l.Lock()
	defer l.Unlock()

	var t Tunnel
	var candidates []Key
	a.store.View(func(st *State) {
		if p := st.tunnel(tunnelID); p != nil {
			t = *p
		}
		for _, k := range st.Keys {
			switch {
			case keyID == "auto" && k.Status == "idle":
				candidates = append(candidates, *k)
			case k.ID == keyID:
				candidates = append(candidates, *k)
			}
		}
	})
	if t.ID == "" {
		return errors.New("隧道不存在")
	}
	if keyID == "none" {
		return a.store.Update(func(st *State) error {
			p := st.tunnel(t.ID)
			if p == nil {
				return nil
			}
			if k := st.key(p.KeyID); k != nil {
				k.Status, k.TunnelID = "idle", ""
			}
			p.KeyID = ""
			return nil
		})
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].LastUsedAt < candidates[j].LastUsedAt })
	if len(candidates) == 0 {
		return errors.New("密钥池中没有可用的空闲密钥")
	}
	var lastErr error
	for _, k := range candidates {
		if k.ID == t.KeyID {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		err := warpApplyLicense(ctx, &t, k.Key)
		var acc *warpAccount
		if err == nil {
			acc, err = warpGetAccount(ctx, &t)
		}
		cancel()
		if err != nil {
			lastErr = err
			a.store.Update(func(st *State) error {
				if p := st.key(k.ID); p != nil {
					p.Status, p.Error = "invalid", err.Error()
				}
				return nil
			})
			a.event("warn", "密钥 %s 绑定到 %s 失败：%v", maskKey(k.Key), t.Name, err)
			continue
		}
		a.store.Update(func(st *State) error {
			p := st.tunnel(tunnelID)
			if p == nil {
				return nil
			}
			if old := st.key(p.KeyID); old != nil && old.ID != k.ID {
				old.Status, old.TunnelID = "idle", ""
			}
			p.KeyID, p.LastError = k.ID, ""
			p.RestartSeq++
			applyAccount(p, acc)
			if nk := st.key(k.ID); nk != nil {
				nk.Status, nk.TunnelID, nk.Error, nk.LastUsedAt = "bound", tunnelID, "", time.Now().Unix()
			}
			st.bump(p.NodeID)
			return nil
		})
		a.event("info", "%s 已更换密钥为 %s（%s）", t.Name, maskKey(k.Key), acc.AccountType)
		return nil
	}
	return fmt.Errorf("所有候选密钥均失败：%v", lastErr)
}

// Reregister 为隧道重新注册 WARP 设备（新的密钥对），并沿用原密钥。
func (a *App) Reregister(id string) error {
	var old Tunnel
	a.store.View(func(st *State) {
		if p := st.tunnel(id); p != nil {
			old = *p
		}
	})
	if old.ID == "" {
		return errors.New("隧道不存在")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	nt, err := warpRegister(ctx)
	if err != nil {
		return err
	}
	warpDeleteDevice(ctx, &old)
	keyID := old.KeyID
	a.store.Update(func(st *State) error {
		p := st.tunnel(id)
		if p == nil {
			return nil
		}
		p.DeviceID, p.Token, p.PrivateKey, p.PeerPublic = nt.DeviceID, nt.Token, nt.PrivateKey, nt.PeerPublic
		p.AddressV4, p.AddressV6, p.ClientID = nt.AddressV4, nt.AddressV6, nt.ClientID
		p.AccountType, p.License, p.PremiumData, p.Quota = nt.AccountType, nt.License, 0, 0
		p.KeyID, p.LastError = "", ""
		if k := st.key(keyID); k != nil {
			k.Status, k.TunnelID = "idle", ""
		}
		st.bump(p.NodeID)
		return nil
	})
	a.event("info", "%s 已重新注册设备", old.Name)
	if keyID != "" {
		if err := a.RotateKey(id, keyID); err != nil {
			a.event("warn", "%s 重新绑定原密钥失败：%v", old.Name, err)
		}
	}
	return nil
}

func (a *App) RefreshAccount(id string) error {
	var t Tunnel
	a.store.View(func(st *State) {
		if p := st.tunnel(id); p != nil {
			t = *p
		}
	})
	if t.ID == "" {
		return errors.New("隧道不存在")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	acc, err := warpGetAccount(ctx, &t)
	if err != nil {
		return err
	}
	revoked := false
	a.store.Update(func(st *State) error {
		p := st.tunnel(id)
		if p == nil {
			return nil
		}
		applyAccount(p, acc)
		if k := st.key(p.KeyID); k != nil && acc.License != k.Key {
			// 账户许可证已不是我们绑定的密钥：密钥被他人顶替或被官方回收
			k.Status, k.Error, k.TunnelID = "invalid", "账户许可证已变更", ""
			p.KeyID = ""
			revoked = true
		}
		return nil
	})
	if revoked {
		a.event("warn", "%s 的密钥已失效", t.Name)
		if a.settings().AutoRotate {
			go a.RotateKey(id, "auto")
		}
	}
	return nil
}

func applyAccount(p *Tunnel, acc *warpAccount) {
	if acc == nil {
		return
	}
	p.AccountType, p.License = acc.AccountType, acc.License
	p.PremiumData, p.Quota = acc.PremiumData, acc.Quota
	p.AccountAt = time.Now().Unix()
}

func maskKey(k string) string {
	if len(k) < 10 {
		return k
	}
	return k[:4] + "****" + k[len(k)-4:]
}

// ---------- 启动迁移 / 后台循环 ----------

// migrate 把单机版（v1）遗留的隧道和规则归到一个「本机」节点下。
func (a *App) migrate() {
	a.store.Update(func(st *State) error {
		// 2.1.4：单个优选 IP 改为列表
		for _, n := range st.Nodes {
			if n.CDNConnectIP != "" && len(n.CDNConnectIPs) == 0 {
				n.CDNConnectIPs = []string{n.CDNConnectIP}
			}
			if n.CDNPreferIP != "" && len(n.CDNPreferIPs) == 0 {
				n.CDNPreferIPs = []string{n.CDNPreferIP}
			}
			n.CDNConnectIP, n.CDNPreferIP = "", ""
		}
		orphan := false
		for _, t := range st.Tunnels {
			orphan = orphan || t.NodeID == ""
		}
		for _, r := range st.Rules {
			orphan = orphan || r.NodeID == ""
		}
		if !orphan {
			return nil
		}
		n := &Node{ID: newID("n_"), Name: "本机（v1 迁移）", PublicHost: st.Settings.PublicHost, CreatedAt: time.Now().Unix(), Version: 1,
			InstallToken: "kwi_" + randHex(16), InstallExpires: time.Now().Add(30 * time.Minute).Unix()}
		st.Nodes = append(st.Nodes, n)
		for _, t := range st.Tunnels {
			if t.NodeID == "" {
				t.NodeID = n.ID
			}
		}
		for _, r := range st.Rules {
			if r.NodeID == "" {
				r.NodeID = n.ID
			}
		}
		log.Printf("已把单机版数据迁移到节点 %s，请在面板为其执行安装命令", n.Name)
		return nil
	})
}

func (a *App) Boot() {
	a.migrate()
	go a.loopOffline()
	go a.loopAccounts()
	go a.loopPersist()
	go a.loopCDNLines()
}

func (a *App) loopOffline() {
	for {
		time.Sleep(10 * time.Second)
		now := time.Now().Unix()
		var off []string
		a.mu.Lock()
		for id, rt := range a.nodes {
			if rt.Online && now-rt.LastSeen > offlineAfter {
				rt.Online = false
				off = append(off, id)
			}
		}
		a.mu.Unlock()
		for _, id := range off {
			name := id
			a.store.View(func(st *State) {
				if n := st.node(id); n != nil {
					name = n.Name
				}
			})
			a.event("error", "节点 %s 已离线（%d 秒未同步）", name, offlineAfter)
		}
	}
}

func (a *App) loopAccounts() {
	for {
		time.Sleep(30 * time.Minute)
		var ids []string
		a.store.View(func(st *State) {
			for _, t := range st.Tunnels {
				ids = append(ids, t.ID)
			}
		})
		for _, id := range ids {
			if err := a.RefreshAccount(id); err != nil && !strings.Contains(err.Error(), "不存在") {
				log.Printf("刷新账户 %s 失败: %v", id, err)
			}
		}
	}
}

// loopPersist 每分钟把规则累计流量写回状态文件。
func (a *App) loopPersist() {
	for {
		time.Sleep(time.Minute)
		a.flushTotals()
		a.metrics.Save()
	}
}

func (a *App) flushTotals() {
	deltas := map[string][2]int64{}
	a.mu.Lock()
	for _, rt := range a.nodes {
		for id, d := range rt.pending {
			if d[0] != 0 || d[1] != 0 {
				x := deltas[id]
				deltas[id] = [2]int64{x[0] + d[0], x[1] + d[1]}
			}
		}
		rt.pending = map[string][2]int64{}
	}
	a.mu.Unlock()
	if len(deltas) == 0 {
		return
	}
	a.store.Update(func(st *State) error {
		for id, d := range deltas {
			if r := st.rule(id); r != nil {
				r.TotalUp += d[0]
				r.TotalDown += d[1]
			}
		}
		return nil
	})
}

// pendingTraffic 返回尚未写回状态文件的规则流量，用于界面实时显示。
func (a *App) pendingTraffic(ruleID string) (int64, int64) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var u, d int64
	for _, rt := range a.nodes {
		p := rt.pending[ruleID]
		u += p[0]
		d += p[1]
	}
	return u, d
}

func (a *App) Shutdown() {
	a.flushTotals()
	a.metrics.Save()
}
