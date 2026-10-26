package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Node 是一台入口 VPS，上面运行 Agent，执行该节点的隧道与转发规则。
type Node struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	PublicHost     string `json:"public_host"` // 用户连接的入口地址（建议仅 DNS 的域名）
	Remark         string `json:"remark"`
	TokenHash      string `json:"token_hash"` // Agent 永久令牌的 SHA-256
	InstallToken   string `json:"install_token"`
	InstallExpires int64  `json:"install_expires"`
	Version        int64  `json:"version"`        // 期望配置版本，任何影响该节点的修改都会递增
	CDNEnabled     bool   `json:"cdn_enabled"`    // 作为 Cloudflare CDN 出口
	CDNDomain      string `json:"cdn_domain"`     // 开了橙色云朵、指向本节点的域名
	CDNPort        int    `json:"cdn_port"`       // Cloudflare 支持的 HTTPS 端口
	CDNSecret      string `json:"cdn_secret"`     // WebSocket 路径密钥
	CDNConnectIP   string `json:"cdn_connect_ip"` // 经本出口的入口连 Cloudflare 时默认使用的优选 IP（可选）
	CDNPreferIP    string `json:"cdn_prefer_ip"`  // 本节点作为入口走 CDN 时使用的优选 IP，优先于出口上的设置
	CDNCert        string `json:"cdn_cert"`       // 源站证书 PEM（可选，SSL 模式为「完全（严格）」时需要）
	CDNKey         string `json:"cdn_key"`        // 源站证书私钥 PEM
	CreatedAt      int64  `json:"created_at"`
	FirstSeen      int64  `json:"first_seen"`
}

// Tunnel 是持久化的 WARP 设备（一个设备 = 一条 WireGuard 隧道），归属于一个节点。
type Tunnel struct {
	ID          string `json:"id"`
	NodeID      string `json:"node_id"`
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	RestartSeq  int    `json:"restart_seq"`
	ProbeSeq    int    `json:"probe_seq"`
	DeviceID    string `json:"device_id"`
	Token       string `json:"token"`
	PrivateKey  string `json:"private_key"`
	PeerPublic  string `json:"peer_public"`
	AddressV4   string `json:"address_v4"`
	AddressV6   string `json:"address_v6"`
	ClientID    string `json:"client_id"`
	Endpoint    string `json:"endpoint"` // 为空时使用全局默认端点
	KeyID       string `json:"key_id"`   // 绑定的密钥池条目
	License     string `json:"license"`
	AccountType string `json:"account_type"`
	PremiumData int64  `json:"premium_data"`
	Quota       int64  `json:"quota"`
	AccountAt   int64  `json:"account_at"`
	CreatedAt   int64  `json:"created_at"`
	LastError   string `json:"last_error"`
}

// Key 是密钥池中的一个 WARP+ 许可证。
type Key struct {
	ID         string `json:"id"`
	Key        string `json:"key"`
	Label      string `json:"label"`
	Status     string `json:"status"` // idle | bound | invalid
	TunnelID   string `json:"tunnel_id"`
	Error      string `json:"error"`
	AddedAt    int64  `json:"added_at"`
	LastUsedAt int64  `json:"last_used_at"`
}

type Rule struct {
	ID         string `json:"id"`
	NodeID     string `json:"node_id"`
	Name       string `json:"name"`
	Enabled    bool   `json:"enabled"`
	Protocol   string `json:"protocol"` // tcp | udp | both
	ListenAddr string `json:"listen_addr"`
	ListenPort int    `json:"listen_port"`
	Target     string `json:"target"`
	TargetPort int    `json:"target_port"`
	Mode       string `json:"mode"` // pool | tunnel | direct | cdn
	TunnelID   string `json:"tunnel_id"`
	CDNExitID  string `json:"cdn_exit_id"` // cdn 模式：经哪个出口节点
	Remark     string `json:"remark"`
	TotalUp    int64  `json:"total_up"`
	TotalDown  int64  `json:"total_down"`
	CreatedAt  int64  `json:"created_at"`
	ProbeSeq   int    `json:"probe_seq"`
}

type Settings struct {
	AdminUser       string `json:"admin_user"`
	AdminHash       string `json:"admin_hash"`
	SessionSecret   string `json:"session_secret"`
	DefaultEndpoint string `json:"default_endpoint"`
	MTU             int    `json:"mtu"`
	ProbeInterval   int    `json:"probe_interval"` // 秒
	FailThreshold   int    `json:"fail_threshold"` // 连续失败次数后重建隧道
	AutoRotate      bool   `json:"auto_rotate"`    // 密钥失效时自动换下一个
	PortMin         int    `json:"port_min"`
	PortMax         int    `json:"port_max"`
	PublicHost      string `json:"public_host"` // v1 遗留：单机版的入口地址，迁移时转给默认节点
	PanelURL        string `json:"panel_url"`   // Agent 连接控制端用的地址（留空按请求推断）
	TelegramToken   string `json:"telegram_token"`
	TelegramChat    string `json:"telegram_chat"`
	PoolStrategy    string `json:"pool_strategy"` // least_conn | latency | round_robin
}

type Event struct {
	Time    int64  `json:"time"`
	Level   string `json:"level"` // info | warn | error
	Message string `json:"message"`
}

type State struct {
	Settings Settings  `json:"settings"`
	Nodes    []*Node   `json:"nodes"`
	Tunnels  []*Tunnel `json:"tunnels"`
	Keys     []*Key    `json:"keys"`
	Rules    []*Rule   `json:"rules"`
	Events   []Event   `json:"events"`
}

type Store struct {
	mu   sync.Mutex
	path string
	S    State
}

func newID(prefix string) string {
	b := make([]byte, 6)
	rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func OpenStore(dir string) (*Store, bool, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, false, err
	}
	s := &Store{path: filepath.Join(dir, "state.json")}
	data, err := os.ReadFile(s.path)
	fresh := false
	switch {
	case errors.Is(err, os.ErrNotExist):
		fresh = true
	case err != nil:
		return nil, false, err
	default:
		if err := json.Unmarshal(data, &s.S); err != nil {
			return nil, false, err
		}
	}
	st := &s.S.Settings
	if st.SessionSecret == "" {
		st.SessionSecret = randHex(32)
	}
	if st.DefaultEndpoint == "" {
		st.DefaultEndpoint = DefaultEndpoint
	}
	if st.MTU == 0 {
		st.MTU = 1280
	}
	if st.ProbeInterval == 0 {
		st.ProbeInterval = 30
	}
	if st.FailThreshold == 0 {
		st.FailThreshold = 3
	}
	if st.PortMin == 0 {
		st.PortMin, st.PortMax = 20000, 29999
	}
	if st.PoolStrategy == "" {
		st.PoolStrategy = "least_conn"
	}
	if fresh {
		st.AutoRotate = true
	}
	return s, fresh, nil
}

// Save 原子写入状态文件；调用方必须持有 mu。
func (s *Store) saveLocked() error {
	data, err := json.MarshalIndent(&s.S, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.S); err != nil {
		return err
	}
	return s.saveLocked()
}

func (s *Store) View(fn func(*State)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.S)
}

func (s *Store) AddEvent(level, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.S.Events = append(s.S.Events, Event{Time: time.Now().Unix(), Level: level, Message: msg})
	if n := len(s.S.Events); n > 500 {
		s.S.Events = append([]Event(nil), s.S.Events[n-500:]...)
	}
	s.saveLocked()
}

func (st *State) node(id string) *Node {
	for _, n := range st.Nodes {
		if n.ID == id {
			return n
		}
	}
	return nil
}

// bump 递增节点配置版本，Agent 下次同步时拉取新配置。
func (st *State) bump(nodeID string) {
	if n := st.node(nodeID); n != nil {
		n.Version++
	}
}

func (st *State) bumpAll() {
	for _, n := range st.Nodes {
		n.Version++
	}
}

func (st *State) tunnel(id string) *Tunnel {
	for _, t := range st.Tunnels {
		if t.ID == id {
			return t
		}
	}
	return nil
}

func (st *State) key(id string) *Key {
	for _, k := range st.Keys {
		if k.ID == id {
			return k
		}
	}
	return nil
}

func (st *State) rule(id string) *Rule {
	for _, r := range st.Rules {
		if r.ID == id {
			return r
		}
	}
	return nil
}
