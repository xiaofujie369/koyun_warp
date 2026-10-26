package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	liveStep = 10  // 秒
	liveCap  = 360 // 1 小时
	dayStep  = 300 // 5 分钟
	dayCap   = 288 // 24 小时
)

type Point struct {
	T int64              `json:"t"`
	V map[string]float64 `json:"v"`
}

type series struct {
	Live []Point               `json:"live"`
	Day  []Point               `json:"day"`
	AccT int64                 `json:"acc_t"`
	Acc  map[string][2]float64 `json:"acc"` // 当前 5 分钟桶的 sum, count
}

type Metrics struct {
	mu   sync.Mutex
	path string
	m    map[string]*series
}

func NewMetrics() *Metrics { return &Metrics{m: map[string]*series{}} }

func (m *Metrics) Load(dir string) {
	m.path = filepath.Join(dir, "metrics.json")
	data, err := os.ReadFile(m.path)
	if err != nil {
		return
	}
	m.mu.Lock()
	json.Unmarshal(data, &m.m)
	if m.m == nil {
		m.m = map[string]*series{}
	}
	m.mu.Unlock()
}

func (m *Metrics) Save() {
	if m.path == "" {
		return
	}
	m.mu.Lock()
	data, err := json.Marshal(m.m)
	m.mu.Unlock()
	if err != nil {
		return
	}
	tmp := m.path + ".tmp"
	if os.WriteFile(tmp, data, 0600) == nil {
		os.Rename(tmp, m.path)
	}
}

func (m *Metrics) Drop(key string) {
	m.mu.Lock()
	delete(m.m, key)
	m.mu.Unlock()
}

// Push 写入一个采样。同一 10 秒内的多个采样会合并到同一点，
// 同时累计到 5 分钟桶用于 24 小时视图。延迟为负值表示失败，不计入平均值。
func (m *Metrics) Push(key string, ts int64, vals map[string]float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.m[key]
	if s == nil {
		s = &series{Acc: map[string][2]float64{}}
		m.m[key] = s
	}
	lt := ts / liveStep * liveStep
	if n := len(s.Live); n > 0 && s.Live[n-1].T == lt {
		for k, v := range vals {
			s.Live[n-1].V[k] = v
		}
	} else {
		cp := make(map[string]float64, len(vals))
		for k, v := range vals {
			cp[k] = v
		}
		s.Live = append(s.Live, Point{T: lt, V: cp})
		if len(s.Live) > liveCap {
			s.Live = s.Live[len(s.Live)-liveCap:]
		}
	}
	dt := ts / dayStep * dayStep
	if s.AccT != 0 && s.AccT != dt {
		s.flushDay()
	}
	s.AccT = dt
	if s.Acc == nil {
		s.Acc = map[string][2]float64{}
	}
	for k, v := range vals {
		a := s.Acc[k]
		if v >= 0 {
			a[0] += v
			a[1]++
		}
		s.Acc[k] = a
	}
}

func (s *series) flushDay() {
	p := Point{T: s.AccT, V: map[string]float64{}}
	for k, a := range s.Acc {
		if a[1] > 0 {
			p.V[k] = a[0] / a[1]
		} else {
			p.V[k] = -1
		}
	}
	s.Day = append(s.Day, p)
	if len(s.Day) > dayCap {
		s.Day = s.Day[len(s.Day)-dayCap:]
	}
	s.Acc = map[string][2]float64{}
}

func (m *Metrics) Get(key, rng string) []Point {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.m[key]
	if s == nil {
		return []Point{}
	}
	src := s.Live
	if rng == "24h" {
		src = s.Day
	}
	out := make([]Point, len(src))
	copy(out, src)
	return out
}

// ---------- 采样器 ----------

type sysSample struct {
	cpuIdle, cpuTotal uint64
	rx, tx            uint64
}

type SysInfo struct {
	CPU       float64 `json:"cpu"`
	MemUsed   uint64  `json:"mem_used"`
	MemTotal  uint64  `json:"mem_total"`
	Load      string  `json:"load"`
	RxRate    float64 `json:"rx_rate"`
	TxRate    float64 `json:"tx_rate"`
	Uptime    int64   `json:"uptime"`
	ProcRSS   uint64  `json:"proc_rss"`
	Goroutine int     `json:"goroutines"`
	Hostname  string  `json:"hostname"`
}

var (
	sysMu   sync.Mutex
	sysLast SysInfo
	started = time.Now()
)

func readSys() sysSample {
	var s sysSample
	if b, err := os.ReadFile("/proc/stat"); err == nil {
		line, _, _ := strings.Cut(string(b), "\n")
		f := strings.Fields(line)
		for i, v := range f[1:] {
			n, _ := strconv.ParseUint(v, 10, 64)
			s.cpuTotal += n
			if i == 3 || i == 4 {
				s.cpuIdle += n
			}
		}
	}
	if b, err := os.ReadFile("/proc/net/dev"); err == nil {
		for _, line := range strings.Split(string(b), "\n")[2:] {
			name, rest, ok := strings.Cut(line, ":")
			name = strings.TrimSpace(name)
			if !ok || name == "lo" || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "br-") {
				continue
			}
			f := strings.Fields(rest)
			if len(f) >= 9 {
				rx, _ := strconv.ParseUint(f[0], 10, 64)
				tx, _ := strconv.ParseUint(f[8], 10, 64)
				s.rx += rx
				s.tx += tx
			}
		}
	}
	return s
}

func memInfo() (used, total uint64) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return
	}
	var avail uint64
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		n, _ := strconv.ParseUint(f[1], 10, 64)
		switch f[0] {
		case "MemTotal:":
			total = n * 1024
		case "MemAvailable:":
			avail = n * 1024
		}
	}
	return total - avail, total
}

func procRSS() uint64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			f := strings.Fields(line)
			n, _ := strconv.ParseUint(f[1], 10, 64)
			return n * 1024
		}
	}
	return 0
}

func getSys() SysInfo {
	sysMu.Lock()
	defer sysMu.Unlock()
	return sysLast
}
