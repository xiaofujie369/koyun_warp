package main

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

func (s *Server) listCDNLines(w http.ResponseWriter, r *http.Request) {
	out := []*CDNLine{}
	s.app.store.View(func(st *State) {
		for _, l := range st.CDNLines {
			c := *l
			out = append(out, &c)
		}
	})
	writeJSON(w, 200, out)
}

func (s *Server) saveCDNLine(w http.ResponseWriter, r *http.Request) {
	var in CDNLine
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	if err := validateCDNLine(&in); err != nil {
		fail(w, 400, err)
		return
	}
	id := r.PathValue("id")
	var saved CDNLine
	err := s.app.store.Update(func(st *State) error {
		for _, o := range st.CDNLines {
			if o.ID != id && o.Domain == in.Domain && o.Port == in.Port && o.Path == in.Path {
				return errors.New("已有相同域名、端口和路径的线路「" + o.Name + "」")
			}
		}
		var old *CDNLine
		if id != "" {
			for _, o := range st.CDNLines {
				if o.ID == id {
					old = o
				}
			}
			if old == nil {
				return errors.New("线路不存在")
			}
			in.ID, in.CreatedAt = old.ID, old.CreatedAt // 配置变了，旧的检测结果作废
			in.RuleID, in.RuleAuto = old.RuleID, old.RuleAuto
		} else {
			in.ID, in.CreatedAt = newID("c_"), time.Now().Unix()
		}
		if err := syncCDNLineRule(st, &in); err != nil {
			return err
		}
		if old != nil {
			*old = in
		} else {
			st.CDNLines = append(st.CDNLines, &in)
		}
		saved = in
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	s.app.event("info", "CDN 线路 %s 已保存：%s:%d → %s", saved.Name, saved.Domain, saved.Port, saved.Origin)
	writeJSON(w, 200, saved)
}

func (s *Server) deleteCDNLine(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var name string
	s.app.store.Update(func(st *State) error {
		for i, o := range st.CDNLines {
			if o.ID == id {
				name = o.Name
				if o.RuleAuto {
					dropRule(st, o.RuleID)
				}
				st.CDNLines = append(st.CDNLines[:i], st.CDNLines[i+1:]...)
				break
			}
		}
		return nil
	})
	if name == "" {
		fail(w, 404, errors.New("线路不存在"))
		return
	}
	s.app.event("info", "CDN 线路 %s 已删除", name)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) testCDNLine(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var l *CDNLine
	s.app.store.View(func(st *State) {
		for _, o := range st.CDNLines {
			if o.ID == id {
				c := *o
				l = &c
			}
		}
	})
	if l == nil {
		fail(w, 404, errors.New("线路不存在"))
		return
	}
	writeJSON(w, 200, s.app.runCDNLineTest(*l))
}

// syncCDNLineRule 让「经入口节点中转」的线路在该节点上有一条 :Port → 落地 的直连规则。
// 节点上已有监听同一端口、目标相同的规则时直接复用（不归本线路管理）；否则自动创建。
func syncCDNLineRule(st *State, l *CDNLine) error {
	var cur *Rule
	for _, r := range st.Rules {
		if r.ID == l.RuleID {
			cur = r
		}
	}
	if l.ViaNodeID == "" {
		if cur != nil && l.RuleAuto {
			dropRule(st, cur.ID)
		}
		l.RuleID, l.RuleAuto = "", false
		return nil
	}
	n := st.node(l.ViaNodeID)
	if n == nil {
		return errors.New("中转节点不存在")
	}
	if n.CDNEnabled && n.CDNPort == l.Port {
		return fmt.Errorf("节点「%s」的 %d 端口已被它的 CDN 出口占用，请换一个端口", n.Name, l.Port)
	}
	// 当前关联的规则若不再匹配（换了节点或端口），先解除
	if cur != nil && (cur.NodeID != l.ViaNodeID || cur.ListenPort != l.Port) {
		if l.RuleAuto {
			dropRule(st, cur.ID)
		}
		cur, l.RuleID, l.RuleAuto = nil, "", false
	}
	if cur == nil {
		for _, r := range st.Rules {
			if r.NodeID == l.ViaNodeID && r.ListenPort == l.Port && r.Protocol != "udp" {
				if r.Target != l.Origin || r.TargetPort != l.OriginPort {
					return fmt.Errorf("节点「%s」的 %d 端口已被规则「%s」占用（转发到 %s:%d）", n.Name, l.Port, r.Name, r.Target, r.TargetPort)
				}
				cur, l.RuleID, l.RuleAuto = r, r.ID, false
			}
		}
	}
	if cur == nil {
		cur = &Rule{ID: newID("r_"), NodeID: l.ViaNodeID, Enabled: true, Protocol: "tcp", ListenAddr: "0.0.0.0", ListenPort: l.Port,
			Mode: "direct", CreatedAt: time.Now().Unix()}
		st.Rules = append(st.Rules, cur)
		l.RuleID, l.RuleAuto = cur.ID, true
	}
	if l.RuleAuto {
		cur.Name = "CDN · " + l.Name
		cur.Target, cur.TargetPort = l.Origin, l.OriginPort
		cur.Remark = "由「CDN 接入」线路自动管理"
	}
	n.Version++
	return nil
}

func dropRule(st *State, id string) {
	for i, r := range st.Rules {
		if r.ID == id {
			if n := st.node(r.NodeID); n != nil {
				n.Version++
			}
			st.Rules = append(st.Rules[:i], st.Rules[i+1:]...)
			return
		}
	}
}
