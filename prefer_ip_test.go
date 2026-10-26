package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	if c := patch(exit.ID, `{"cdn_enabled":true,"cdn_domain":"cdn.example.com","cdn_port":2096,"cdn_connect_ip":"104.16.1.1"}`); c != http.StatusOK {
		t.Fatal("enable exit", c)
	}
	st.Update(func(s *State) error {
		s.Rules = append(s.Rules, &Rule{ID: "r1", NodeID: entry.ID, Mode: "cdn", CDNExitID: exit.ID, Protocol: "tcp", Enabled: true, Target: "1.2.3.4", TargetPort: 443})
		return nil
	})
	ip := func() string { return a.BuildConfig(entry.ID).CDNRoutes[exit.ID].ConnectIP }
	if ip() != "104.16.1.1" {
		t.Fatal("出口默认值未生效", ip())
	}
	v0 := a.BuildConfig(entry.ID).Version
	if c := patch(entry.ID, `{"cdn_prefer_ip":"104.17.2.2"}`); c != http.StatusOK || ip() != "104.17.2.2" {
		t.Fatal("入口优选 IP 未生效", c, ip())
	}
	if a.BuildConfig(entry.ID).Version == v0 {
		t.Fatal("版本未递增，Agent 不会拉取新配置")
	}
	if c := patch(entry.ID, `{"cdn_prefer_ip":"104.17.2.2:443"}`); c != http.StatusBadRequest {
		t.Fatal("带端口应被拒绝", c)
	}
	if c := patch(entry.ID, `{"cdn_prefer_ip":""}`); c != http.StatusOK || ip() != "104.16.1.1" {
		t.Fatal("清空后应回落到出口默认值", c, ip())
	}
}
