package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

//go:embed web
var webFS embed.FS

const cookieName = "kw_sess"

type Server struct {
	app      *App
	mu       sync.Mutex
	failures map[string]*loginFail
}

type loginFail struct {
	n     int
	until time.Time
}

func (a *App) Handler() http.Handler {
	s := &Server{app: a, failures: map[string]*loginFail{}}
	mux := http.NewServeMux()
	sub, _ := fs.Sub(webFS, "web")
	static := http.FileServer(http.FS(sub))
	mux.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		static.ServeHTTP(w, r)
	}))

	mux.HandleFunc("POST /kw/login", s.login)
	mux.HandleFunc("POST /kw/logout", s.logout)
	mux.HandleFunc("GET /kw/me", s.auth(s.me))

	mux.HandleFunc("GET /kw/overview", s.auth(s.overview))
	mux.HandleFunc("GET /kw/series", s.auth(s.series))
	mux.HandleFunc("GET /kw/events", s.auth(s.events))

	mux.HandleFunc("GET /kw/tunnels", s.auth(s.listTunnels))
	mux.HandleFunc("POST /kw/tunnels", s.auth(s.createTunnel))
	mux.HandleFunc("PATCH /kw/tunnels/{id}", s.auth(s.patchTunnel))
	mux.HandleFunc("DELETE /kw/tunnels/{id}", s.auth(s.deleteTunnel))
	mux.HandleFunc("POST /kw/tunnels/{id}/{op}", s.auth(s.tunnelOp))
	mux.HandleFunc("GET /kw/tunnels/{id}/wireguard", s.auth(s.tunnelConf))

	mux.HandleFunc("GET /kw/keys", s.auth(s.listKeys))
	mux.HandleFunc("POST /kw/keys", s.auth(s.importKeys))
	mux.HandleFunc("DELETE /kw/keys/{id}", s.auth(s.deleteKey))
	mux.HandleFunc("POST /kw/keys/{id}/reset", s.auth(s.resetKey))

	mux.HandleFunc("GET /kw/rules", s.auth(s.listRules))
	mux.HandleFunc("POST /kw/rules", s.auth(s.saveRule))
	mux.HandleFunc("PUT /kw/rules/{id}", s.auth(s.saveRule))
	mux.HandleFunc("DELETE /kw/rules/{id}", s.auth(s.deleteRule))
	mux.HandleFunc("POST /kw/rules/{id}/{op}", s.auth(s.ruleOp))

	mux.HandleFunc("GET /kw/nodes", s.auth(s.listNodes))
	mux.HandleFunc("POST /kw/nodes", s.auth(s.createNode))
	mux.HandleFunc("PATCH /kw/nodes/{id}", s.auth(s.patchNode))
	mux.HandleFunc("DELETE /kw/nodes/{id}", s.auth(s.deleteNode))
	mux.HandleFunc("POST /kw/nodes/{id}/install", s.auth(s.nodeInstall))

	// Agent 与安装接口：不走管理员会话，分别用 Agent 令牌和短期安装凭证鉴权
	mux.HandleFunc("POST /kw/agent/sync", s.agentSync)
	mux.HandleFunc("POST /kw/agent/register", s.agentRegister)
	mux.HandleFunc("GET /kw/i/{token}", s.installScript)
	mux.HandleFunc("GET /kw/i/{token}/bin/{arch}", s.installBinary)

	mux.HandleFunc("GET /kw/settings", s.auth(s.getSettings))
	mux.HandleFunc("PUT /kw/settings", s.auth(s.putSettings))
	mux.HandleFunc("POST /kw/password", s.auth(s.changePassword))
	mux.HandleFunc("POST /kw/notify-test", s.auth(s.notifyTest))

	return secHeaders(mux)
}

func secHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		h.ServeHTTP(w, r)
	})
}

// ---------- 工具 ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("请求格式错误：%w", err)
	}
	return nil
}

func clientIP(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		// 经 Cloudflare → 本机反代：CF-Connecting-IP 才是真实访客
		if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); net.ParseIP(cf) != nil {
			return cf
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			return strings.TrimSpace(first)
		}
	}
	return host
}

// ---------- 会话 ----------

func (s *Server) sign(payload string) string {
	var secret string
	s.app.store.View(func(st *State) { secret = st.Settings.SessionSecret + st.Settings.AdminHash })
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Server) issue(w http.ResponseWriter, r *http.Request, user string) {
	exp := time.Now().Add(7 * 24 * time.Hour).Unix()
	payload := base64.RawURLEncoding.EncodeToString([]byte(user + "|" + strconv.FormatInt(exp, 10)))
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: payload + "." + s.sign(payload), Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		Expires: time.Unix(exp, 0),
	})
}

func (s *Server) session(r *http.Request) (string, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", false
	}
	payload, sig, ok := strings.Cut(c.Value, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(s.sign(payload))) {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", false
	}
	user, expS, _ := strings.Cut(string(raw), "|")
	exp, _ := strconv.ParseInt(expS, 10, 64)
	if time.Now().Unix() > exp {
		return "", false
	}
	return user, true
}

// auth 校验会话；修改类请求额外要求自定义请求头，跨站表单无法伪造。
func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.session(r); !ok {
			fail(w, 401, errors.New("未登录或会话已过期"))
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-KW") != "1" {
			fail(w, 403, errors.New("缺少请求校验头"))
			return
		}
		h(w, r)
	}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	s.mu.Lock()
	f := s.failures[ip]
	if f != nil && time.Now().Before(f.until) {
		s.mu.Unlock()
		fail(w, 429, fmt.Errorf("登录失败次数过多，请 %d 秒后再试", int(time.Until(f.until).Seconds())+1))
		return
	}
	s.mu.Unlock()
	var req struct{ Username, Password string }
	if err := readJSON(r, &req); err != nil {
		fail(w, 400, err)
		return
	}
	var user, hash string
	s.app.store.View(func(st *State) { user, hash = st.Settings.AdminUser, st.Settings.AdminHash })
	if req.Username != user || bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		s.mu.Lock()
		if f == nil || time.Now().After(f.until) && f.n >= 5 {
			f = &loginFail{}
			s.failures[ip] = f
		}
		f.n++
		if f.n >= 5 {
			f.until = time.Now().Add(5 * time.Minute)
		}
		s.mu.Unlock()
		s.app.event("warn", "来自 %s 的登录失败", ip)
		fail(w, 401, errors.New("用户名或密码错误"))
		return
	}
	s.mu.Lock()
	delete(s.failures, ip)
	s.mu.Unlock()
	s.issue(w, r, user)
	writeJSON(w, 200, map[string]string{"user": user})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	u, _ := s.session(r)
	writeJSON(w, 200, map[string]string{"user": u})
}

// ---------- 视图组装 ----------

func (s *Server) nodeNames() map[string]string {
	m := map[string]string{}
	s.app.store.View(func(st *State) {
		for _, n := range st.Nodes {
			m[n.ID] = n.Name
		}
	})
	return m
}

func (s *Server) nodeViews() []map[string]any {
	a := s.app
	var ns []Node
	counts := map[string][2]int{}
	a.store.View(func(st *State) {
		for _, n := range st.Nodes {
			ns = append(ns, *n)
		}
		for _, t := range st.Tunnels {
			c := counts[t.NodeID]
			c[0]++
			counts[t.NodeID] = c
		}
		for _, r := range st.Rules {
			c := counts[r.NodeID]
			c[1]++
			counts[r.NodeID] = c
		}
	})
	now := time.Now().Unix()
	out := make([]map[string]any, 0, len(ns))
	for _, n := range ns {
		v := map[string]any{
			"id": n.ID, "name": n.Name, "public_host": n.PublicHost, "remark": n.Remark, "created_at": n.CreatedAt,
			"first_seen": n.FirstSeen, "version": n.Version, "tunnels": counts[n.ID][0], "rules": counts[n.ID][1],
			"installed": n.TokenHash != "", "status": "pending",
			"cdn_enabled": n.CDNEnabled, "cdn_domain": n.CDNDomain, "cdn_port": n.CDNPort, "cdn_connect_ips": n.CDNConnectIPs,
			"cdn_cert_info": certInfo(n.CDNCert), "cdn_prefer_ips": n.CDNPreferIPs,
		}
		if rt := a.nodeRT(n.ID); rt != nil {
			a.mu.RLock()
			rep := rt.Report
			v["last_seen"], v["ip"], v["applied"] = rt.LastSeen, rt.IP, rep.Applied
			v["agent_version"], v["arch"], v["os"], v["hostname"], v["sys"], v["apply_err"] = rep.Version, rep.Arch, rep.OS, rep.Hostname, rep.Sys, rep.ApplyErr
			v["cdn"], v["cdn_ips"] = rep.CDN, rep.CDNIPs
			a.mu.RUnlock()
			if now-rt.LastSeen <= offlineAfter {
				v["status"] = "online"
			} else {
				v["status"] = "offline"
			}
		} else if n.FirstSeen != 0 {
			v["status"] = "offline"
		}
		out = append(out, v)
	}
	return out
}

func (s *Server) tunnelViews() []map[string]any {
	a := s.app
	var ts []Tunnel
	keys := map[string]string{}
	a.store.View(func(st *State) {
		for _, t := range st.Tunnels {
			ts = append(ts, *t)
		}
		for _, k := range st.Keys {
			keys[k.ID] = maskKey(k.Key)
		}
	})
	names := s.nodeNames()
	now := time.Now().Unix()
	out := make([]map[string]any, 0, len(ts))
	for _, t := range ts {
		v := map[string]any{
			"id": t.ID, "name": t.Name, "enabled": t.Enabled, "address_v4": t.AddressV4, "address_v6": t.AddressV6,
			"endpoint_cfg": t.Endpoint, "key_id": t.KeyID, "key": keys[t.KeyID], "license": maskKey(t.License),
			"account_type": t.AccountType, "premium_data": t.PremiumData, "quota": t.Quota, "account_at": t.AccountAt,
			"created_at": t.CreatedAt, "last_error": t.LastError, "device_id": t.DeviceID,
			"node_id": t.NodeID, "node_name": names[t.NodeID],
		}
		var snap map[string]any
		if rt := a.nodeRT(t.NodeID); rt != nil {
			a.mu.RLock()
			if now-rt.LastSeen <= offlineAfter {
				snap = rt.tunnels[t.ID]
			}
			a.mu.RUnlock()
		}
		switch {
		case !t.Enabled:
			v["rt"] = map[string]any{"status": "disabled"}
		case snap != nil:
			v["rt"] = snap
		default:
			v["rt"] = map[string]any{"status": "unknown", "error": "节点离线或尚未同步"}
		}
		out = append(out, v)
	}
	return out
}

func (s *Server) ruleViews() []map[string]any {
	a := s.app
	var rs []Rule
	hosts := map[string]string{}
	a.store.View(func(st *State) {
		for _, r := range st.Rules {
			rs = append(rs, *r)
		}
		for _, n := range st.Nodes {
			hosts[n.ID] = n.PublicHost
		}
	})
	names := s.nodeNames()
	now := time.Now().Unix()
	out := make([]map[string]any, 0, len(rs))
	for _, r := range rs {
		v := map[string]any{"rule": r, "node_name": names[r.NodeID], "entry_host": hosts[r.NodeID]}
		pu, pd := a.pendingTraffic(r.ID)
		v["total_up"], v["total_down"] = r.TotalUp+pu, r.TotalDown+pd
		if rt := a.nodeRT(r.NodeID); rt != nil && r.Enabled {
			a.mu.RLock()
			if now-rt.LastSeen <= offlineAfter {
				if snap := rt.rules[r.ID]; snap != nil {
					v["rt"] = snap
				}
			} else {
				v["offline"] = true
			}
			a.mu.RUnlock()
		}
		out = append(out, v)
	}
	return out
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	a := s.app
	var keyStats = map[string]int{}
	var events []Event
	var strategy, panelURL string
	a.store.View(func(st *State) {
		strategy, panelURL = st.Settings.PoolStrategy, st.Settings.PanelURL
		for _, k := range st.Keys {
			keyStats[k.Status]++
		}
		n := len(st.Events)
		events = append([]Event(nil), st.Events[max(0, n-12):]...)
	})
	sort.Slice(events, func(i, j int) bool { return events[i].Time > events[j].Time })
	writeJSON(w, 200, map[string]any{
		"sys":           getSys(),
		"nodes":         s.nodeViews(),
		"tunnels":       s.tunnelViews(),
		"rules":         s.ruleViews(),
		"keys":          keyStats,
		"events":        events,
		"pool_strategy": strategy,
		"panel_url":     panelURL,
		"now":           time.Now().Unix(),
	})
}

func (s *Server) series(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key != "system" && !strings.HasPrefix(key, "tunnel:") && !strings.HasPrefix(key, "rule:") && !strings.HasPrefix(key, "node:") {
		fail(w, 400, errors.New("key 无效"))
		return
	}
	if key == "system" {
		writeJSON(w, 200, s.systemSeries(r.URL.Query().Get("range")))
		return
	}
	writeJSON(w, 200, s.app.metrics.Get(key, r.URL.Query().Get("range")))
}

// systemSeries 把所有节点的转发流量和连接数按时间点相加。
func (s *Server) systemSeries(rng string) []Point {
	var ids []string
	s.app.store.View(func(st *State) {
		for _, n := range st.Nodes {
			ids = append(ids, n.ID)
		}
	})
	sum := map[int64]map[string]float64{}
	for _, id := range ids {
		for _, p := range s.app.metrics.Get("node:"+id, rng) {
			m := sum[p.T]
			if m == nil {
				m = map[string]float64{}
				sum[p.T] = m
			}
			for _, k := range []string{"fwd_up", "fwd_down", "conns"} {
				if v, ok := p.V[k]; ok && v >= 0 {
					m[k] += v
				}
			}
		}
	}
	out := make([]Point, 0, len(sum))
	for t, v := range sum {
		out = append(out, Point{T: t, V: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].T < out[j].T })
	return out
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	var ev []Event
	s.app.store.View(func(st *State) { ev = append([]Event(nil), st.Events...) })
	sort.Slice(ev, func(i, j int) bool { return ev[i].Time > ev[j].Time })
	writeJSON(w, 200, ev)
}

// ---------- 隧道 ----------

func (s *Server) listTunnels(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.tunnelViews())
}

func validEndpoint(ep string) error {
	if ep == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(ep)
	if err != nil || host == "" {
		return errors.New("端点格式应为 IP:端口 或 域名:端口")
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return errors.New("端点端口无效")
	}
	return nil
}

func (s *Server) createTunnel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeID   string `json:"node_id"`
		Name     string `json:"name"`
		Endpoint string `json:"endpoint"`
		KeyID    string `json:"key_id"`
		Count    int    `json:"count"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, 400, err)
		return
	}
	if err := validEndpoint(req.Endpoint); err != nil {
		fail(w, 400, err)
		return
	}
	req.Count = min(max(req.Count, 1), 10)
	var created []string
	var errs []string
	for i := 0; i < req.Count; i++ {
		name := req.Name
		if name != "" && req.Count > 1 {
			name = fmt.Sprintf("%s-%d", req.Name, i+1)
		}
		t, err := s.app.CreateTunnel(req.NodeID, name, req.Endpoint, req.KeyID)
		if t != nil {
			created = append(created, t.Name)
		}
		if err != nil {
			errs = append(errs, err.Error())
			if t == nil && i == 0 {
				break
			}
		}
	}
	if len(created) == 0 {
		fail(w, 502, fmt.Errorf("注册失败：%s", strings.Join(errs, "; ")))
		return
	}
	writeJSON(w, 200, map[string]any{"created": created, "errors": errs})
}

func (s *Server) patchTunnel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Name     *string `json:"name"`
		Endpoint *string `json:"endpoint"`
		Enabled  *bool   `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, 400, err)
		return
	}
	if req.Endpoint != nil {
		*req.Endpoint = strings.TrimSpace(*req.Endpoint)
		if err := validEndpoint(*req.Endpoint); err != nil {
			fail(w, 400, err)
			return
		}
	}
	err := s.app.store.Update(func(st *State) error {
		t := st.tunnel(id)
		if t == nil {
			return errors.New("隧道不存在")
		}
		if req.Name != nil && strings.TrimSpace(*req.Name) != "" {
			t.Name = strings.TrimSpace(*req.Name)
		}
		if req.Endpoint != nil {
			t.Endpoint = *req.Endpoint
		}
		if req.Enabled != nil {
			t.Enabled = *req.Enabled
		}
		st.bump(t.NodeID)
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) deleteTunnel(w http.ResponseWriter, r *http.Request) {
	if err := s.app.DeleteTunnel(r.PathValue("id")); err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) tunnelOp(w http.ResponseWriter, r *http.Request) {
	id, op := r.PathValue("id"), r.PathValue("op")
	var err error
	bumpSeq := func(restart bool) error {
		return s.app.store.Update(func(st *State) error {
			t := st.tunnel(id)
			if t == nil {
				return errors.New("隧道不存在")
			}
			if restart {
				t.RestartSeq++
			} else {
				t.ProbeSeq++
			}
			st.bump(t.NodeID)
			return nil
		})
	}
	switch op {
	case "rotate":
		var req struct {
			KeyID string `json:"key_id"`
		}
		readJSON(r, &req)
		if req.KeyID == "" {
			req.KeyID = "auto"
		}
		err = s.app.RotateKey(id, req.KeyID)
	case "restart":
		err = bumpSeq(true)
	case "probe":
		err = bumpSeq(false)
	case "reregister":
		err = s.app.Reregister(id)
	case "refresh":
		err = s.app.RefreshAccount(id)
	default:
		fail(w, 404, errors.New("未知操作"))
		return
	}
	if err != nil {
		fail(w, 502, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) tunnelConf(w http.ResponseWriter, r *http.Request) {
	var t Tunnel
	var ep string
	s.app.store.View(func(st *State) {
		if p := st.tunnel(r.PathValue("id")); p != nil {
			t = *p
			ep = p.Endpoint
			if ep == "" {
				ep = st.Settings.DefaultEndpoint
			}
		}
	})
	if t.ID == "" {
		fail(w, 404, errors.New("隧道不存在"))
		return
	}
	cid, _ := base64.StdEncoding.DecodeString(t.ClientID)
	res := ""
	if len(cid) >= 3 {
		res = fmt.Sprintf("# Reserved = %d, %d, %d\n", cid[0], cid[1], cid[2])
	}
	addr := t.AddressV4 + "/32"
	if t.AddressV6 != "" {
		addr += ", " + t.AddressV6 + "/128"
	}
	conf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = 1.1.1.1, 1.0.0.1\nMTU = 1280\n%s\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = %s\nPersistentKeepalive = 25\n",
		t.PrivateKey, addr, res, t.PeerPublic, ep)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "warp-"+t.ID+".conf"))
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(conf))
}

// ---------- 密钥池 ----------

var keyRe = regexp.MustCompile(`\b[A-Za-z0-9]{8}-[A-Za-z0-9]{8}-[A-Za-z0-9]{8}\b`)

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request) {
	var out []map[string]any
	s.app.store.View(func(st *State) {
		names := map[string]string{}
		for _, t := range st.Tunnels {
			names[t.ID] = t.Name
		}
		for _, k := range st.Keys {
			out = append(out, map[string]any{
				"id": k.ID, "key": maskKey(k.Key), "label": k.Label, "status": k.Status, "tunnel_id": k.TunnelID,
				"tunnel_name": names[k.TunnelID], "error": k.Error, "added_at": k.AddedAt, "last_used_at": k.LastUsedAt,
			})
		}
	})
	if out == nil {
		out = []map[string]any{}
	}
	writeJSON(w, 200, out)
}

func (s *Server) importKeys(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text  string `json:"text"`
		Label string `json:"label"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, 400, err)
		return
	}
	found := keyRe.FindAllString(req.Text, -1)
	if len(found) == 0 {
		fail(w, 400, errors.New("没有识别到 WARP+ 密钥（格式 xxxxxxxx-xxxxxxxx-xxxxxxxx）"))
		return
	}
	added, dup := 0, 0
	s.app.store.Update(func(st *State) error {
		have := map[string]bool{}
		for _, k := range st.Keys {
			have[k.Key] = true
		}
		for _, k := range found {
			if have[k] {
				dup++
				continue
			}
			have[k] = true
			st.Keys = append(st.Keys, &Key{ID: newID("k_"), Key: k, Label: strings.TrimSpace(req.Label), Status: "idle", AddedAt: time.Now().Unix()})
			added++
		}
		return nil
	})
	s.app.event("info", "密钥池导入 %d 个密钥（重复 %d）", added, dup)
	writeJSON(w, 200, map[string]int{"added": added, "duplicate": dup})
}

func (s *Server) deleteKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := s.app.store.Update(func(st *State) error {
		for i, k := range st.Keys {
			if k.ID == id {
				if k.Status == "bound" {
					return errors.New("密钥正在被隧道使用，请先为该隧道更换密钥")
				}
				st.Keys = append(st.Keys[:i], st.Keys[i+1:]...)
				return nil
			}
		}
		return errors.New("密钥不存在")
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) resetKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := s.app.store.Update(func(st *State) error {
		k := st.key(id)
		if k == nil {
			return errors.New("密钥不存在")
		}
		if k.Status == "invalid" {
			k.Status, k.Error = "idle", ""
		}
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// ---------- 规则 ----------

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.ruleViews())
}

func protoOverlap(a, b string) bool {
	return a == b || a == "both" || b == "both"
}

func (s *Server) saveRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in Rule
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Target = strings.Trim(strings.TrimSpace(in.Target), "[]")
	in.Remark = strings.TrimSpace(in.Remark)
	if in.Protocol == "" {
		in.Protocol = "both"
	}
	if in.Mode == "" {
		in.Mode = "pool"
	}
	set := s.app.settings()
	var saved Rule
	err := s.app.store.Update(func(st *State) error {
		if st.node(in.NodeID) == nil {
			return errors.New("请选择入口节点")
		}
		if in.Mode == "tunnel" {
			t := st.tunnel(in.TunnelID)
			if t == nil {
				return errors.New("选择的隧道不存在")
			}
			if t.NodeID != in.NodeID {
				return errors.New("固定隧道必须属于同一个节点")
			}
		} else {
			in.TunnelID = ""
		}
		if in.Mode == "cdn" {
			ex := st.node(in.CDNExitID)
			if ex == nil || !ex.CDNEnabled {
				return errors.New("请选择已开启 CDN 出口的节点")
			}
		} else {
			in.CDNExitID = ""
		}
		used := map[int]string{}
		for _, o := range st.Rules {
			if o.ID != id && o.NodeID == in.NodeID && protoOverlap(o.Protocol, in.Protocol) {
				used[o.ListenPort] = o.Name
			}
		}
		if in.ListenPort == 0 {
			for p := set.PortMin; p <= set.PortMax; p++ {
				if _, taken := used[p]; !taken {
					in.ListenPort = p
					break
				}
			}
			if in.ListenPort == 0 {
				return errors.New("端口范围内没有空闲端口")
			}
		}
		if n, taken := used[in.ListenPort]; taken {
			return fmt.Errorf("端口 %d 已被该节点的规则「%s」占用", in.ListenPort, n)
		}
		if n := st.node(in.NodeID); n != nil && n.CDNEnabled && n.CDNPort == in.ListenPort && in.Protocol != "udp" {
			return fmt.Errorf("端口 %d 已被该节点的 CDN 出口占用", in.ListenPort)
		}
		if err := validateRule(&in, set); err != nil {
			return err
		}
		if in.Name == "" {
			in.Name = fmt.Sprintf("%s:%d", in.Target, in.TargetPort)
		}
		if id == "" {
			in.ID = newID("r_")
			in.CreatedAt = time.Now().Unix()
			in.Enabled = true
			in.TotalUp, in.TotalDown, in.ProbeSeq = 0, 0, 0
			st.Rules = append(st.Rules, &in)
			st.bump(in.NodeID)
			if in.Mode == "cdn" {
				st.bumpAll()
			}
			saved = in
			return nil
		}
		old := st.rule(id)
		if old == nil {
			return errors.New("规则不存在")
		}
		if old.NodeID != in.NodeID {
			st.bump(old.NodeID)
		}
		in.ID, in.CreatedAt, in.TotalUp, in.TotalDown, in.Enabled, in.ProbeSeq = old.ID, old.CreatedAt, old.TotalUp, old.TotalDown, old.Enabled, old.ProbeSeq
		if old.Mode == "cdn" || in.Mode == "cdn" {
			st.bumpAll()
		}
		*old = in
		st.bump(in.NodeID)
		saved = in
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	s.app.event("info", "规则 %s 已保存：:%d → %s（%s）", saved.Name, saved.ListenPort, saved.targetAddr(), saved.Mode)
	writeJSON(w, 200, saved)
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var name string
	err := s.app.store.Update(func(st *State) error {
		for i, x := range st.Rules {
			if x.ID == id {
				name = x.Name
				st.Rules = append(st.Rules[:i], st.Rules[i+1:]...)
				st.bump(x.NodeID)
				if x.Mode == "cdn" {
					st.bumpAll()
				}
				return nil
			}
		}
		return errors.New("规则不存在")
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	s.app.metrics.Drop("rule:" + id)
	s.app.event("info", "已删除规则 %s", name)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) ruleOp(w http.ResponseWriter, r *http.Request) {
	id, op := r.PathValue("id"), r.PathValue("op")
	err := s.app.store.Update(func(st *State) error {
		x := st.rule(id)
		if x == nil {
			return errors.New("规则不存在")
		}
		switch op {
		case "enable", "disable":
			x.Enabled = op == "enable"
			if x.Mode == "cdn" {
				st.bumpAll()
			}
		case "probe":
			x.ProbeSeq++
		case "reset-traffic":
			x.TotalUp, x.TotalDown = 0, 0
			return nil
		default:
			return errors.New("未知操作")
		}
		st.bump(x.NodeID)
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	if op == "reset-traffic" {
		s.app.mu.Lock()
		for _, rt := range s.app.nodes {
			delete(rt.pending, id)
		}
		s.app.mu.Unlock()
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	st := s.app.settings()
	tg := ""
	if st.TelegramToken != "" {
		tg = maskKey(st.TelegramToken)
	}
	writeJSON(w, 200, map[string]any{
		"admin_user": st.AdminUser, "default_endpoint": st.DefaultEndpoint, "mtu": st.MTU,
		"probe_interval": st.ProbeInterval, "fail_threshold": st.FailThreshold, "auto_rotate": st.AutoRotate,
		"port_min": st.PortMin, "port_max": st.PortMax, "panel_url": st.PanelURL,
		"telegram_token": tg, "telegram_chat": st.TelegramChat, "pool_strategy": st.PoolStrategy,
	})
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		DefaultEndpoint string `json:"default_endpoint"`
		MTU             int    `json:"mtu"`
		ProbeInterval   int    `json:"probe_interval"`
		FailThreshold   int    `json:"fail_threshold"`
		AutoRotate      bool   `json:"auto_rotate"`
		PortMin         int    `json:"port_min"`
		PortMax         int    `json:"port_max"`
		PanelURL        string `json:"panel_url"`
		TelegramToken   string `json:"telegram_token"`
		TelegramChat    string `json:"telegram_chat"`
		PoolStrategy    string `json:"pool_strategy"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	in.DefaultEndpoint = strings.TrimSpace(in.DefaultEndpoint)
	switch {
	case validEndpoint(in.DefaultEndpoint) != nil || in.DefaultEndpoint == "":
		fail(w, 400, errors.New("默认端点格式无效"))
		return
	case in.MTU < 1100 || in.MTU > 1500:
		fail(w, 400, errors.New("MTU 需在 1100-1500 之间"))
		return
	case in.ProbeInterval < 10 || in.ProbeInterval > 600:
		fail(w, 400, errors.New("探测间隔需在 10-600 秒之间"))
		return
	case in.FailThreshold < 1 || in.FailThreshold > 20:
		fail(w, 400, errors.New("失败阈值需在 1-20 之间"))
		return
	case in.PortMin < 1 || in.PortMax > 65535 || in.PortMin > in.PortMax:
		fail(w, 400, errors.New("端口范围无效"))
		return
	}
	switch in.PoolStrategy {
	case "least_conn", "latency", "round_robin":
	default:
		fail(w, 400, errors.New("负载策略无效"))
		return
	}
	in.PanelURL = strings.TrimRight(strings.TrimSpace(in.PanelURL), "/")
	if in.PanelURL != "" {
		if u, err := url.Parse(in.PanelURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			fail(w, 400, errors.New("Agent 连接地址应形如 https://warp.example.com"))
			return
		}
	}
	s.app.store.Update(func(st *State) error {
		c := &st.Settings
		if c.MTU != in.MTU || c.DefaultEndpoint != in.DefaultEndpoint || c.ProbeInterval != in.ProbeInterval ||
			c.FailThreshold != in.FailThreshold || c.PoolStrategy != in.PoolStrategy {
			st.bumpAll()
		}
		c.DefaultEndpoint, c.MTU, c.ProbeInterval, c.FailThreshold = in.DefaultEndpoint, in.MTU, in.ProbeInterval, in.FailThreshold
		c.AutoRotate, c.PortMin, c.PortMax, c.PanelURL = in.AutoRotate, in.PortMin, in.PortMax, in.PanelURL
		c.TelegramChat, c.PoolStrategy = strings.TrimSpace(in.TelegramChat), in.PoolStrategy
		// 前端回显的是掩码；只有提交了新值时才覆盖
		if in.TelegramToken == "" {
			c.TelegramToken = ""
		} else if !strings.Contains(in.TelegramToken, "****") {
			c.TelegramToken = strings.TrimSpace(in.TelegramToken)
		}
		return nil
	})
	s.app.event("info", "系统设置已更新")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Old      string `json:"old"`
		New      string `json:"new"`
		Username string `json:"username"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, 400, err)
		return
	}
	var hash string
	s.app.store.View(func(st *State) { hash = st.Settings.AdminHash })
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Old)) != nil {
		fail(w, 400, errors.New("原密码错误"))
		return
	}
	if len(req.New) < 10 {
		fail(w, 400, errors.New("新密码至少 10 位"))
		return
	}
	nh, _ := bcrypt.GenerateFromPassword([]byte(req.New), 12)
	user := strings.TrimSpace(req.Username)
	s.app.store.Update(func(st *State) error {
		st.Settings.AdminHash = string(nh)
		if user != "" {
			st.Settings.AdminUser = user
		}
		return nil
	})
	s.app.event("info", "管理员凭据已修改")
	// 签名密钥包含密码哈希，修改后旧会话全部失效，这里为当前会话重新签发
	var u string
	s.app.store.View(func(st *State) { u = st.Settings.AdminUser })
	s.issue(w, r, u)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) notifyTest(w http.ResponseWriter, r *http.Request) {
	st := s.app.settings()
	if st.TelegramToken == "" || st.TelegramChat == "" {
		fail(w, 400, errors.New("请先保存 Telegram Bot Token 与 Chat ID"))
		return
	}
	s.app.notify("测试通知：告警通道工作正常")
	writeJSON(w, 200, map[string]bool{"ok": true})
}
