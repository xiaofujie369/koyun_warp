package main

import (
	"errors"
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
		if id == "" {
			in.ID, in.CreatedAt = newID("c_"), time.Now().Unix()
			st.CDNLines = append(st.CDNLines, &in)
			saved = in
			return nil
		}
		for _, o := range st.CDNLines {
			if o.ID == id {
				in.ID, in.CreatedAt, in.Test = o.ID, o.CreatedAt, nil // 配置变了，旧的检测结果作废
				*o = in
				saved = in
				return nil
			}
		}
		return errors.New("线路不存在")
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
