package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCDNPreferIP(t *testing.T) {
	st, _, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := NewApp(st)
	s := &Server{app: a, failures: map[string]*loginFail{}}
	entry, _ := a.CreateNode("入口", "in.example.com", "")
	exit, _ := a.CreateNode("出口", "out.example.com", "")
	patch := func(id, body string) int {
		req := httptest.NewRequest("PATCH", "/kw/nodes/"+id, strings.NewReader(body))
		req.SetPathValue("id", id)
		w := httptest.NewRecorder()
		s.patchNode(w, req)
		return w.Code
	}
	if c := patch(exit.ID, `{"cdn_enabled":true,"cdn_domain":"cdn.example.com","cdn_port":2096,"cdn_connect_ips":["104.16.1.1"]}`); c != http.StatusOK {
		t.Fatal("enable exit", c)
	}
	st.Update(func(s *State) error {
		s.Rules = append(s.Rules, &Rule{ID: "r1", NodeID: entry.ID, Mode: "cdn", CDNExitID: exit.ID, Protocol: "tcp", Enabled: true, Target: "1.2.3.4", TargetPort: 443})
		return nil
	})
	ip := func() string { return strings.Join(a.BuildConfig(entry.ID).CDNRoutes[exit.ID].ConnectIPs, ",") }
	if ip() != "104.16.1.1" {
		t.Fatal("出口默认值未生效", ip())
	}
	v0 := a.BuildConfig(entry.ID).Version
	if c := patch(entry.ID, `{"cdn_prefer_ips":["104.17.2.2"," 104.18.3.3 ","104.17.2.2",""]}`); c != http.StatusOK || ip() != "104.17.2.2,104.18.3.3" {
		t.Fatal("入口优选 IP 未生效", c, ip())
	}
	if a.BuildConfig(entry.ID).Version == v0 {
		t.Fatal("版本未递增，Agent 不会拉取新配置")
	}
	if c := patch(entry.ID, `{"cdn_prefer_ips":["104.17.2.2:443"]}`); c != http.StatusBadRequest {
		t.Fatal("带端口应被拒绝", c)
	}
	if c := patch(entry.ID, `{"cdn_prefer_ips":[]}`); c != http.StatusOK || ip() != "104.16.1.1" {
		t.Fatal("清空后应回落到出口默认值", c, ip())
	}
}

func TestCDNIPPoolRoundRobinAndCooldown(t *testing.T) {
	p := newCDNIPPool()
	ips := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	seen := map[string]int{}
	for i := 0; i < 6; i++ {
		seen[p.order(ips)[0]]++
	}
	for _, ip := range ips {
		if seen[ip] != 2 {
			t.Fatal("轮询不均匀", seen)
		}
	}
	p.state("2.2.2.2").coolUntil.Store(time.Now().Add(time.Minute).UnixMilli())
	for i := 0; i < 6; i++ {
		o := p.order(ips)
		if o[0] == "2.2.2.2" || o[2] != "2.2.2.2" {
			t.Fatal("暂停中的 IP 应排在最后", o)
		}
	}
}

func TestMigrateSingleIP(t *testing.T) {
	st, _, _ := OpenStore(t.TempDir())
	st.Update(func(s *State) error {
		s.Nodes = append(s.Nodes, &Node{ID: "n1", CDNConnectIP: "104.16.1.1", CDNPreferIP: "104.17.1.1"})
		return nil
	})
	a := NewApp(st)
	a.migrate()
	st.View(func(s *State) {
		n := s.node("n1")
		if strings.Join(n.CDNConnectIPs, ",") != "104.16.1.1" || strings.Join(n.CDNPreferIPs, ",") != "104.17.1.1" || n.CDNConnectIP != "" {
			t.Fatal("迁移失败", n.CDNConnectIPs, n.CDNPreferIPs)
		}
	})
}

func TestCFPortAllowedOutsideRange(t *testing.T) {
	set := Settings{PortMin: 20000, PortMax: 29999}
	r := Rule{ListenPort: 2083, TargetPort: 2083, Target: "1.2.3.4", Protocol: "tcp", Mode: "direct"}
	if err := validateRule(&r, set); err != nil {
		t.Fatal("Cloudflare 端口应允许", err)
	}
	r.ListenPort = 3000
	if err := validateRule(&r, set); err == nil {
		t.Fatal("范围外的普通端口应拒绝")
	}
}
