package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// AgentConfig 是控制端下发给某个节点的完整期望配置。
type AgentConfig struct {
	Version         int64               `json:"version"`
	NodeID          string              `json:"node_id"`
	NodeName        string              `json:"node_name"`
	MTU             int                 `json:"mtu"`
	ProbeInterval   int                 `json:"probe_interval"`
	FailThreshold   int                 `json:"fail_threshold"`
	PoolStrategy    string              `json:"pool_strategy"`
	DefaultEndpoint string              `json:"default_endpoint"`
	Tunnels         []TunnelSpec        `json:"tunnels"`
	Rules           []Rule              `json:"rules"`
	CDNExit         *CDNExitCfg         `json:"cdn_exit"`   // 本节点作为 CDN 出口时的配置
	CDNRoutes       map[string]CDNRoute `json:"cdn_routes"` // 出口节点 ID -> 入口连接地址
}

// TunnelSpec 是 Agent 运行一条 WARP 隧道所需的全部参数（不含账户令牌）。
type TunnelSpec struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	PrivateKey string `json:"private_key"`
	PeerPublic string `json:"peer_public"`
	AddressV4  string `json:"address_v4"`
	AddressV6  string `json:"address_v6"`
	ClientID   string `json:"client_id"`
	Endpoint   string `json:"endpoint"`
	RestartSeq int    `json:"restart_seq"`
	ProbeSeq   int    `json:"probe_seq"`
}

func (s TunnelSpec) runKey(mtu int) string {
	return fmt.Sprint(s.PrivateKey, s.PeerPublic, s.AddressV4, s.AddressV6, s.ClientID, s.Endpoint, s.RestartSeq, mtu)
}

func ruleRunKey(r Rule) string {
	return fmt.Sprint(r.Enabled, r.Protocol, r.ListenAddr, r.ListenPort, r.Target, r.TargetPort, r.Mode, r.TunnelID, r.CDNExitID)
}

// AgentReport 是 Agent 每次同步时上报的运行状态。
type AgentReport struct {
	Applied  int64            `json:"applied"`
	Boot     string           `json:"boot"`
	Version  string           `json:"version"`
	Hostname string           `json:"hostname"`
	Arch     string           `json:"arch"`
	OS       string           `json:"os"`
	Sys      SysInfo          `json:"sys"`
	Tunnels  []map[string]any `json:"tunnels"`
	Rules    []map[string]any `json:"rules"`
	Events   []Event          `json:"events"`
	ApplyErr string           `json:"apply_err"`
	CDN      map[string]any   `json:"cdn"`
}

type syncResp struct {
	Version int64        `json:"version"`
	Config  *AgentConfig `json:"config"`
}

type Agent struct {
	server, token, dir string
	hc                 *http.Client

	mu       sync.RWMutex
	cfg      AgentConfig
	tunnels  map[string]*TunnelRT
	tunSpec  map[string]TunnelSpec
	tunKey   map[string]string
	rules    map[string]*RuleRT
	ruleKey  map[string]string
	probeSeq map[string]int
	rr       atomic.Uint64
	applyErr string
	cdnExit  *CDNExit
	cdnKey   string

	evMu   sync.Mutex
	events []Event
	boot   string

	tunnelOps sync.Map
}

func NewAgent(server, token, dir string) *Agent {
	return &Agent{
		server: strings.TrimRight(server, "/"), token: token, dir: dir,
		hc:      &http.Client{Timeout: 20 * time.Second},
		tunnels: map[string]*TunnelRT{}, tunSpec: map[string]TunnelSpec{}, tunKey: map[string]string{},
		rules: map[string]*RuleRT{}, ruleKey: map[string]string{}, probeSeq: map[string]int{},
		boot: randHex(8),
	}
}

func (a *Agent) event(level, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("[%s] %s", level, msg)
	a.evMu.Lock()
	a.events = append(a.events, Event{Time: time.Now().Unix(), Level: level, Message: msg})
	if len(a.events) > 200 {
		a.events = a.events[len(a.events)-200:]
	}
	a.evMu.Unlock()
}

func (a *Agent) conf() AgentConfig {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cfg
}

func (a *Agent) tunnelLock(id string) *sync.Mutex {
	m, _ := a.tunnelOps.LoadOrStore(id, &sync.Mutex{})
	return m.(*sync.Mutex)
}

func (a *Agent) tunnelRT(id string) *TunnelRT {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.tunnels[id]
}

// ---------- 配置应用 ----------

func (a *Agent) cachePath() string { return filepath.Join(a.dir, "config.json") }

// Apply 把运行状态收敛到给定配置：只重启参数变化的隧道和规则。
func (a *Agent) Apply(cfg AgentConfig) {
	if cfg.MTU == 0 {
		cfg.MTU = 1280
	}
	if cfg.ProbeInterval == 0 {
		cfg.ProbeInterval = 30
	}
	if cfg.FailThreshold == 0 {
		cfg.FailThreshold = 3
	}
	a.mu.Lock()
	a.cfg = cfg
	a.mu.Unlock()

	var errs []string
	want := map[string]bool{}
	var wg sync.WaitGroup
	var emu sync.Mutex
	for _, sp := range cfg.Tunnels {
		want[sp.ID] = true
		key := sp.runKey(cfg.MTU)
		a.mu.Lock()
		changed := a.tunKey[sp.ID] != key || a.tunnels[sp.ID] == nil
		probe := a.tunSpec[sp.ID].ProbeSeq != sp.ProbeSeq
		a.tunSpec[sp.ID] = sp
		a.mu.Unlock()
		if changed {
			wg.Add(1)
			go func(sp TunnelSpec) {
				defer wg.Done()
				l := a.tunnelLock(sp.ID)
				l.Lock()
				defer l.Unlock()
				if err := a.startTunnel(sp); err != nil {
					emu.Lock()
					errs = append(errs, fmt.Sprintf("隧道 %s：%v", sp.Name, err))
					emu.Unlock()
					a.event("error", "启动隧道 %s 失败：%v", sp.Name, err)
					return
				}
				a.mu.Lock()
				a.tunKey[sp.ID] = key
				a.mu.Unlock()
			}(sp)
		} else if probe {
			if rt := a.tunnelRT(sp.ID); rt != nil {
				go a.probeTunnel(rt, true)
			}
		}
	}
	wg.Wait()
	a.mu.RLock()
	var gone []string
	for id := range a.tunSpec {
		if !want[id] {
			gone = append(gone, id)
		}
	}
	a.mu.RUnlock()
	for _, id := range gone {
		a.stopTunnel(id)
		a.mu.Lock()
		delete(a.tunSpec, id)
		delete(a.tunKey, id)
		a.mu.Unlock()
	}

	wantR := map[string]bool{}
	for _, r := range cfg.Rules {
		wantR[r.ID] = true
		key := ruleRunKey(r)
		a.mu.RLock()
		old := a.rules[r.ID]
		changed := a.ruleKey[r.ID] != key || old == nil || (r.Enabled && old.closed.Load())
		probe := a.probeSeq[r.ID] != r.ProbeSeq
		a.mu.RUnlock()
		if changed {
			if err := a.applyRule(r); err != nil {
				errs = append(errs, fmt.Sprintf("规则 %s：%v", r.Name, err))
				a.event("error", "规则 %s 启动失败：%v", r.Name, err)
			}
			a.mu.Lock()
			a.ruleKey[r.ID] = key
			a.mu.Unlock()
		} else {
			// 名称等不影响运行的字段直接更新，不中断连接
			old.rule.Name, old.rule.Remark = r.Name, r.Remark
			if probe && !old.closed.Load() {
				go a.probeRule(old)
			}
		}
		a.mu.Lock()
		a.probeSeq[r.ID] = r.ProbeSeq
		a.mu.Unlock()
	}
	a.mu.RLock()
	var goneR []string
	for id := range a.rules {
		if !wantR[id] {
			goneR = append(goneR, id)
		}
	}
	a.mu.RUnlock()
	for _, id := range goneR {
		a.removeRule(id)
		a.mu.Lock()
		delete(a.ruleKey, id)
		delete(a.probeSeq, id)
		a.mu.Unlock()
	}

	if err := a.applyCDNExit(cfg.CDNExit); err != nil {
		errs = append(errs, err.Error())
		a.event("error", "%v", err)
	}

	a.mu.Lock()
	a.applyErr = strings.Join(errs, "；")
	a.mu.Unlock()
	if data, err := json.Marshal(cfg); err == nil {
		tmp := a.cachePath() + ".tmp"
		if os.WriteFile(tmp, data, 0600) == nil {
			os.Rename(tmp, a.cachePath())
		}
	}
}

// applyCDNExit 启动、更新或停止本节点的 CDN 出口；只有端口、密钥、域名变化时才重启监听。
func (a *Agent) applyCDNExit(c *CDNExitCfg) error {
	a.mu.Lock()
	cur, curKey := a.cdnExit, a.cdnKey
	a.mu.Unlock()
	if c == nil {
		if cur != nil {
			cur.Close()
			a.mu.Lock()
			a.cdnExit, a.cdnKey = nil, ""
			a.mu.Unlock()
			a.event("info", "CDN 出口已关闭")
		}
		return nil
	}
	key := fmt.Sprint(c.Port, c.Secret, c.Domain, c.Cert, c.Key)
	if cur != nil && curKey == key {
		cur.SetAllowed(c.Allowed)
		return nil
	}
	if cur != nil {
		cur.Close()
	}
	e, err := StartCDNExit(*c)
	a.mu.Lock()
	a.cdnExit, a.cdnKey = e, key
	if err != nil {
		a.cdnExit, a.cdnKey = nil, ""
	}
	a.mu.Unlock()
	if err != nil {
		return err
	}
	a.event("info", "CDN 出口已在端口 %d 监听（%s）", c.Port, c.Domain)
	return nil
}

// ---------- 隧道 ----------

func (a *Agent) startTunnel(sp TunnelSpec) error {
	cfg := a.conf()
	ep := sp.Endpoint
	if ep == "" {
		ep = cfg.DefaultEndpoint
	}
	if ep == "" {
		ep = DefaultEndpoint
	}
	a.stopTunnel(sp.ID)
	t := &Tunnel{ID: sp.ID, PrivateKey: sp.PrivateKey, PeerPublic: sp.PeerPublic, AddressV4: sp.AddressV4, AddressV6: sp.AddressV6, ClientID: sp.ClientID}
	rt, err := StartTunnel(t, ep, cfg.MTU)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.tunnels[sp.ID] = rt
	a.mu.Unlock()
	go a.probeTunnel(rt, true)
	return nil
}

func (a *Agent) stopTunnel(id string) {
	a.mu.Lock()
	rt := a.tunnels[id]
	delete(a.tunnels, id)
	a.mu.Unlock()
	if rt != nil {
		rt.Close()
	}
}

func (a *Agent) probeTunnel(rt *TunnelRT, withTrace bool) {
	ms, err := rt.probe(6 * time.Second)
	rt.readStats()
	now := time.Now().Unix()
	cfg := a.conf()
	name := a.tunnelName(rt.ID)
	rt.mu.Lock()
	prev := rt.Status
	rt.LastProbe = now
	if err != nil {
		rt.Fails++
		rt.Err = err.Error()
		if rt.Fails >= max(cfg.FailThreshold, 1) {
			rt.Status = "down"
		} else if prev == "up" {
			rt.Status = "degraded"
		}
	} else {
		rt.Fails, rt.Err, rt.LatencyMs, rt.LastOK = 0, "", ms, now
		rt.Status = "up"
	}
	status, fails := rt.Status, rt.Fails
	needTrace := err == nil && (withTrace || now-rt.TraceAt > 300)
	rt.mu.Unlock()

	if prev != status && (status == "down" || (status == "up" && prev != "starting")) {
		if status == "down" {
			a.event("error", "隧道 %s 不可用：%v", name, err)
		} else {
			a.event("info", "隧道 %s 已恢复，延迟 %.0fms", name, ms)
		}
	}
	if needTrace {
		if tr, err := rt.trace(); err == nil {
			rt.mu.Lock()
			rt.EgressIP, rt.Colo, rt.WarpMode, rt.TraceAt = tr["ip"], tr["colo"], tr["warp"], now
			rt.mu.Unlock()
		}
	}
	// 连续失败达到阈值：重建隧道（重新解析端点、重新握手），保留失败计数以便持续告警
	if err != nil && fails > 0 && cfg.FailThreshold > 0 && fails%cfg.FailThreshold == 0 {
		go func() {
			l := a.tunnelLock(rt.ID)
			if !l.TryLock() {
				return
			}
			defer l.Unlock()
			if a.tunnelRT(rt.ID) != rt {
				return
			}
			a.mu.RLock()
			sp, ok := a.tunSpec[rt.ID]
			a.mu.RUnlock()
			if !ok {
				return
			}
			a.event("warn", "隧道 %s 连续失败 %d 次，正在重建", name, fails)
			if err := a.startTunnel(sp); err != nil {
				a.event("error", "重建隧道 %s 失败：%v", name, err)
				return
			}
			if nrt := a.tunnelRT(rt.ID); nrt != nil {
				nrt.mu.Lock()
				nrt.Fails, nrt.Status = fails, status
				nrt.mu.Unlock()
			}
		}()
	}
}

// ---------- 连接选路 ----------

type dialer func(ctx context.Context, network, addr string) (net.Conn, *TunnelRT, error)

func (a *Agent) dialerFor(r *Rule) dialer {
	switch r.Mode {
	case "direct":
		return func(ctx context.Context, network, addr string) (net.Conn, *TunnelRT, error) {
			var d net.Dialer
			c, err := d.DialContext(ctx, network, addr)
			return c, nil, err
		}
	case "cdn":
		exit := r.CDNExitID
		return func(ctx context.Context, network, addr string) (net.Conn, *TunnelRT, error) {
			if network != "tcp" {
				return nil, nil, errors.New("CDN 模式只支持 TCP")
			}
			rt, ok := a.conf().CDNRoutes[exit]
			if !ok || rt.URL == "" {
				return nil, nil, errors.New("CDN 出口未配置或未启用")
			}
			c, err := cdnDial(ctx, rt, addr)
			return c, nil, err
		}
	case "tunnel":
		id := r.TunnelID
		return func(ctx context.Context, network, addr string) (net.Conn, *TunnelRT, error) {
			rt := a.tunnelRT(id)
			if rt == nil {
				return nil, nil, errors.New("指定隧道未运行")
			}
			c, err := rt.DialContext(ctx, network, addr)
			return c, rt, err
		}
	default:
		return func(ctx context.Context, network, addr string) (net.Conn, *TunnelRT, error) {
			cands := a.poolCandidates()
			if len(cands) == 0 {
				return nil, nil, errors.New("隧道池中没有可用隧道")
			}
			var lastErr error
			for i, rt := range cands {
				if i >= 3 {
					break
				}
				c, err := rt.DialContext(ctx, network, addr)
				if err == nil {
					return c, rt, nil
				}
				lastErr = err
				if ctx.Err() != nil {
					break
				}
			}
			return nil, nil, lastErr
		}
	}
}

// poolCandidates 按策略对本节点的健康隧道排序，第一个为首选，其余为故障转移顺序。
func (a *Agent) poolCandidates() []*TunnelRT {
	strategy := a.conf().PoolStrategy
	a.mu.RLock()
	var up, other []*TunnelRT
	for _, rt := range a.tunnels {
		rt.mu.Lock()
		st := rt.Status
		rt.mu.Unlock()
		switch st {
		case "up":
			up = append(up, rt)
		case "degraded", "starting":
			other = append(other, rt)
		}
	}
	a.mu.RUnlock()
	sort.Slice(up, func(i, j int) bool { return up[i].ID < up[j].ID })
	switch strategy {
	case "latency":
		sort.SliceStable(up, func(i, j int) bool { return up[i].LatencyMs < up[j].LatencyMs })
	case "round_robin":
		if n := len(up); n > 0 {
			off := int(a.rr.Add(1) % uint64(n))
			up = append(up[off:], up[:off]...)
		}
	default:
		sort.SliceStable(up, func(i, j int) bool { return up[i].Active.Load() < up[j].Active.Load() })
	}
	return append(up, other...)
}

// ---------- 主循环 ----------

func (a *Agent) Run() {
	// 先用本地缓存的配置恢复转发：控制端暂时不可达时节点照常工作
	if data, err := os.ReadFile(a.cachePath()); err == nil {
		var cfg AgentConfig
		if json.Unmarshal(data, &cfg) == nil {
			log.Printf("使用本地缓存配置 v%d 启动", cfg.Version)
			a.Apply(cfg)
		}
	}
	a.event("info", "Agent %s 已启动", version)
	go a.loopProbe()
	go a.loopSys()
	backoff := 5 * time.Second
	for {
		if err := a.syncOnce(); err != nil {
			log.Printf("同步失败：%v", err)
			time.Sleep(backoff)
			if backoff < 60*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = 5 * time.Second
		time.Sleep(5 * time.Second)
	}
}

func (a *Agent) loopProbe() {
	for {
		// 尚未拿到配置时间隔为 0，必须兜底，否则会空转占满 CPU
		iv := a.conf().ProbeInterval
		if iv < 10 {
			iv = 30
		}
		time.Sleep(time.Duration(iv) * time.Second)
		a.mu.RLock()
		var ts []*TunnelRT
		for _, rt := range a.tunnels {
			ts = append(ts, rt)
		}
		var rs []*RuleRT
		for _, r := range a.rules {
			rs = append(rs, r)
		}
		a.mu.RUnlock()
		for _, rt := range ts {
			go a.probeTunnel(rt, false)
		}
		for _, r := range rs {
			go a.probeRule(r)
		}
	}
}

// loopSys 每 10 秒计算一次系统 CPU、内存和网卡速率。
func (a *Agent) loopSys() {
	prev := readSys()
	prevT := time.Now()
	host, _ := os.Hostname()
	for {
		time.Sleep(10 * time.Second)
		now := time.Now()
		dt := now.Sub(prevT).Seconds()
		prevT = now
		cur := readSys()
		info := SysInfo{Hostname: host, Uptime: int64(time.Since(started).Seconds()), ProcRSS: procRSS(), Goroutine: runtime.NumGoroutine()}
		if dTot := cur.cpuTotal - prev.cpuTotal; dTot > 0 {
			info.CPU = 100 * float64(dTot-(cur.cpuIdle-prev.cpuIdle)) / float64(dTot)
		}
		info.RxRate = float64(cur.rx-prev.rx) / dt
		info.TxRate = float64(cur.tx-prev.tx) / dt
		prev = cur
		info.MemUsed, info.MemTotal = memInfo()
		if b, err := os.ReadFile("/proc/loadavg"); err == nil {
			if f := strings.Fields(string(b)); len(f) >= 3 {
				info.Load = strings.Join(f[:3], " ")
			}
		}
		sysMu.Lock()
		sysLast = info
		sysMu.Unlock()
	}
}

func (a *Agent) report() AgentReport {
	host, _ := os.Hostname()
	r := AgentReport{Boot: a.boot, Version: version, Hostname: host, Arch: runtime.GOARCH, OS: runtime.GOOS, Sys: getSys()}
	a.mu.RLock()
	r.Applied = a.cfg.Version
	r.ApplyErr = a.applyErr
	for _, t := range a.tunnels {
		t.readStats()
		s := t.Snapshot()
		s["id"] = t.ID
		r.Tunnels = append(r.Tunnels, s)
	}
	for _, rr := range a.rules {
		r.Rules = append(r.Rules, rr.Snapshot())
	}
	if a.cdnExit != nil {
		r.CDN = a.cdnExit.Snapshot()
	}
	a.mu.RUnlock()
	a.evMu.Lock()
	r.Events = a.events
	a.events = nil
	a.evMu.Unlock()
	return r
}

func (a *Agent) syncOnce() error {
	rep := a.report()
	body, _ := json.Marshal(rep)
	req, _ := http.NewRequest("POST", a.server+"/kw/agent/sync", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.hc.Do(req)
	if err != nil {
		a.requeue(rep.Events)
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode != 200 {
		a.requeue(rep.Events)
		return fmt.Errorf("控制端返回 %d：%.200s", resp.StatusCode, data)
	}
	var sr syncResp
	if err := json.Unmarshal(data, &sr); err != nil {
		return err
	}
	if sr.Config != nil && sr.Config.Version != a.conf().Version {
		log.Printf("应用配置 v%d", sr.Config.Version)
		a.Apply(*sr.Config)
	}
	return nil
}

// requeue 在上报失败时把事件放回队列，下次一起发送。
func (a *Agent) requeue(ev []Event) {
	if len(ev) == 0 {
		return
	}
	a.evMu.Lock()
	a.events = append(ev, a.events...)
	if len(a.events) > 200 {
		a.events = a.events[len(a.events)-200:]
	}
	a.evMu.Unlock()
}

// registerAgent 用一次性安装凭证向控制端换取永久 Agent 令牌。
func registerAgent(server, install string) (string, error) {
	body, _ := json.Marshal(map[string]string{"install_token": install})
	cl := &http.Client{Timeout: 20 * time.Second}
	resp, err := cl.Post(strings.TrimRight(server, "/")+"/kw/agent/register", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var out struct {
		Token string `json:"token"`
		Error string `json:"error"`
	}
	json.Unmarshal(data, &out)
	if resp.StatusCode != 200 || out.Token == "" {
		if out.Error == "" {
			out.Error = fmt.Sprintf("控制端返回 %d：%.120s", resp.StatusCode, data)
		}
		return "", errors.New(out.Error)
	}
	return out.Token, nil
}
