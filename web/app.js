"use strict";
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ---------- 主题 ----------
(function initTheme() {
  try { const t = localStorage.getItem("kw-theme"); if (t) document.documentElement.dataset.theme = t; } catch {}
})();
$("#themeBtn").onclick = () => {
  const root = document.documentElement;
  const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme = dark ? "light" : "dark";
  try { localStorage.setItem("kw-theme", root.dataset.theme); } catch {}
  render();
};

// ---------- API ----------
async function api(path, opts = {}) {
  const init = { method: opts.method || "GET", headers: { "X-KW": "1" }, credentials: "same-origin" };
  if (opts.body !== undefined) { init.headers["Content-Type"] = "application/json"; init.body = JSON.stringify(opts.body); }
  const res = await fetch("/kw" + path, init);
  if (res.status === 401 && path !== "/login") { showLogin(); throw new Error("未登录"); }
  const ct = res.headers.get("content-type") || "";
  const data = ct.includes("json") ? await res.json() : await res.text();
  if (!res.ok) throw new Error((data && data.error) || res.statusText);
  return data;
}

function toast(msg, bad) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast show" + (bad ? " bad" : "");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (t.className = "toast"), bad ? 5000 : 2600);
}

async function act(btn, fn, okMsg) {
  if (btn) btn.disabled = true;
  try { const r = await fn(); if (okMsg) toast(okMsg); await refresh(); return r; }
  catch (e) { toast(e.message, true); }
  finally { if (btn) btn.disabled = false; }
}

// ---------- 格式化 ----------
const fmtBytes = (n) => {
  n = Number(n) || 0;
  const u = ["B", "KB", "MB", "GB", "TB", "PB"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(n >= 100 ? 0 : n >= 10 ? 1 : 2) : n) + " " + u[i];
};
const fmtRate = (n) => fmtBytes(n) + "/s";
const fmtMs = (n) => (n == null || n < 0 ? "—" : n < 10 ? n.toFixed(1) + " ms" : Math.round(n) + " ms");
const ago = (ts) => {
  if (!ts) return "—";
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 60) return s + " 秒前"; if (s < 3600) return Math.floor(s / 60) + " 分钟前";
  if (s < 86400) return Math.floor(s / 3600) + " 小时前"; return Math.floor(s / 86400) + " 天前";
};
const dur = (s) => { s = Math.floor(s); const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return d ? `${d}天${h}时` : h ? `${h}时${m}分` : `${m}分`; };
const tstr = (ts, withDate) => { const d = new Date(ts * 1000); const p = (x) => String(x).padStart(2, "0"); return (withDate ? `${p(d.getMonth() + 1)}-${p(d.getDate())} ` : "") + `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`; };
const STATUS = { up: "在线", degraded: "抖动", down: "离线", starting: "启动中", disabled: "已停用", unknown: "未同步", online: "在线", offline: "离线", pending: "待安装" };
const KEYST = { idle: "空闲", bound: "使用中", invalid: "失效" };
const MODE = { pool: "WARP 隧道池", tunnel: "固定 WARP 隧道", cdn: "Cloudflare CDN", direct: "直连" };
const PROTO = { tcp: "TCP", udp: "UDP", both: "TCP+UDP" };
const STRAT = { least_conn: "最少连接", latency: "最低延迟", round_robin: "轮询" };
const cssVar = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();

// ---------- 图表 ----------
// series: [{key, label, color, fmt}]；points: [{t, v:{...}}]
function lineChart(el, points, series, opts = {}) {
  const h = opts.height || 200, W = el.clientWidth || 600, padL = opts.compact ? 0 : 58, padB = opts.compact ? 0 : 22, padT = 8;
  const w = Math.max(50, W - padL - (opts.compact ? 0 : 8));
  const fmt = series[0].fmt || ((v) => v.toFixed(1));
  if (!points.length) { el.innerHTML = `<div class="empty" style="height:${h}px;padding-top:${h / 2 - 12}px">${opts.compact ? "" : "暂无数据，采样每 10 秒一次"}</div>`; return; }
  const t0 = points[0].t, t1 = points[points.length - 1].t || t0 + 1;
  let ymax = 0;
  for (const p of points) for (const s of series) { const v = p.v[s.key]; if (v > ymax) ymax = v; }
  ymax = ymax <= 0 ? 1 : niceMax(ymax);
  const X = (t) => padL + (t1 === t0 ? w : ((t - t0) / (t1 - t0)) * w);
  const Y = (v) => padT + (h - padT - padB) * (1 - v / ymax);
  const step = opts.step || 10;
  let svg = `<svg viewBox="0 0 ${W} ${h}" height="${h}" preserveAspectRatio="none">`;
  if (!opts.compact) {
    for (let i = 0; i <= 4; i++) {
      const v = (ymax / 4) * i, y = Y(v);
      svg += `<line class="grid-l" x1="${padL}" x2="${padL + w}" y1="${y}" y2="${y}"/><text class="ax" x="${padL - 6}" y="${y + 3}" text-anchor="end">${esc(fmt(v))}</text>`;
    }
    const ticks = 5;
    for (let i = 0; i <= ticks; i++) {
      const t = t0 + ((t1 - t0) / ticks) * i;
      svg += `<text class="ax" x="${X(t)}" y="${h - 5}" text-anchor="${i === 0 ? "start" : i === ticks ? "end" : "middle"}">${tstr(t, opts.range === "24h").slice(0, opts.range === "24h" ? 11 : 5)}</text>`;
    }
  }
  for (const s of series) {
    // 缺失或失败（<0）的点断开折线，避免误导
    let d = "", area = "", seg = [], prevT = null;
    const flush = () => {
      if (seg.length) {
        d += "M" + seg.map((p) => p.join(",")).join("L");
        if (s.fill) area += `M${seg[0][0]},${Y(0)}L` + seg.map((p) => p.join(",")).join("L") + `L${seg[seg.length - 1][0]},${Y(0)}Z`;
      }
      seg = [];
    };
    for (const p of points) {
      const v = p.v[s.key];
      if (prevT != null && p.t - prevT > step * 3) flush();
      prevT = p.t;
      if (v == null || v < 0) { flush(); continue; }
      seg.push([X(p.t).toFixed(1), Y(v).toFixed(1)]);
    }
    flush();
    if (area) svg += `<path d="${area}" fill="${s.color}" opacity=".12"/>`;
    svg += `<path d="${d}" fill="none" stroke="${s.color}" stroke-width="${opts.compact ? 1.6 : 1.8}" stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>`;
    // 失败点标记
    if (s.key === "latency" && !opts.compact) for (const p of points) if (p.v.latency != null && p.v.latency < 0) svg += `<rect x="${X(p.t) - 1}" y="${padT}" width="2" height="${h - padT - padB}" fill="${cssVar("--bad")}" opacity=".35"/>`;
  }
  svg += `<line class="cursor" x1="0" x2="0" y1="${padT}" y2="${h - padB}" stroke="${cssVar("--muted")}" stroke-dasharray="3 3" opacity="0"/></svg>`;
  el.innerHTML = `<div class="chart">${svg}<div class="tip hidden"></div></div>`;
  if (opts.compact) return;
  const box = $(".chart", el), tip = $(".tip", el), cur = $(".cursor", el), svgEl = $("svg", el);
  box.onmousemove = (e) => {
    const rect = svgEl.getBoundingClientRect(), x = ((e.clientX - rect.left) / rect.width) * W;
    let best = points[0];
    for (const p of points) if (Math.abs(X(p.t) - x) < Math.abs(X(best.t) - x)) best = p;
    cur.setAttribute("x1", X(best.t)); cur.setAttribute("x2", X(best.t)); cur.setAttribute("opacity", "1");
    tip.innerHTML = `<b>${tstr(best.t, true)}</b>` + series.map((s) => { const v = best.v[s.key]; return `<div><span style="color:${s.color}">●</span> ${esc(s.label)}：${v == null ? "—" : v < 0 ? "失败" : esc((s.fmt || fmt)(v))}</div>`; }).join("");
    tip.classList.remove("hidden");
    const px = (X(best.t) / W) * rect.width;
    tip.style.left = Math.min(rect.width - tip.offsetWidth - 4, Math.max(0, px + 12)) + "px";
    tip.style.top = "6px";
  };
  box.onmouseleave = () => { tip.classList.add("hidden"); cur.setAttribute("opacity", "0"); };
}
function niceMax(v) { const e = Math.pow(10, Math.floor(Math.log10(v))); const m = v / e; return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 2.5 ? 2.5 : m <= 5 ? 5 : 10) * e; }
const legend = (series) => `<div class="legend">${series.map((s) => `<span><i style="background:${s.color}"></i>${esc(s.label)}</span>`).join("")}</div>`;

// ---------- 状态 ----------
let state = { page: "dashboard", ov: null, keys: [], settings: null, mon: { key: "system", range: "1h" }, evFilter: "", ruleQ: "", nodeFilter: "" };
let timer = null;

function showLogin() {
  $("#shell").classList.add("hidden");
  $("#login").classList.remove("hidden");
  clearInterval(timer); timer = null;
}
$("#loginForm").onsubmit = async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  $("#loginErr").textContent = "";
  try {
    const r = await api("/login", { method: "POST", body: { username: f.get("username"), password: f.get("password") } });
    start(r.user);
  } catch (err) { $("#loginErr").textContent = err.message; }
};
$("#logoutBtn").onclick = async () => { await api("/logout", { method: "POST" }).catch(() => {}); showLogin(); };
$("#menuBtn").onclick = () => $("#side").classList.toggle("open");

function start(user) {
  $("#whoami").textContent = user;
  $("#login").classList.add("hidden");
  $("#shell").classList.remove("hidden");
  route();
  clearInterval(timer);
  timer = setInterval(() => { if (!document.hidden && $("#modal").classList.contains("hidden")) refresh(true); }, 5000);
}

window.addEventListener("hashchange", route);
function route() {
  const p = (location.hash.match(/^#\/(\w+)/) || [])[1] || "dashboard";
  state.page = p;
  $$(".side nav a").forEach((a) => a.classList.toggle("on", a.dataset.page === p));
  $("#pageTitle").textContent = $(`.side nav a[data-page="${p}"]`)?.textContent.trim() || "概览";
  $("#side").classList.remove("open");
  $("#view").innerHTML = `<div class="empty">加载中…</div>`;
  refresh();
}

async function refresh(auto) {
  try {
    const jobs = [api("/overview").then((d) => (state.ov = d))];
    if (state.page === "keys" || state.page === "tunnels") jobs.push(api("/keys").then((d) => (state.keys = d)));
    if (state.page === "settings" && !auto) jobs.push(api("/settings").then((d) => (state.settings = d)));
    if (state.page === "events") jobs.push(api("/events").then((d) => (state.events = d)));
    await Promise.all(jobs);
    $("#liveDot").classList.remove("off");
    if (auto && state.page === "settings") return; // 避免覆盖正在编辑的表单
    await render();
  } catch (e) {
    $("#liveDot").classList.add("off");
    if (e.message !== "未登录" && !auto) toast(e.message, true);
  }
}

async function render() {
  if (!state.ov) return;
  const fn = PAGES[state.page] || PAGES.dashboard;
  const keepScroll = window.scrollY;
  await fn($("#view"));
  window.scrollTo(0, keepScroll);
}

// ---------- 页面 ----------
const PAGES = {};

PAGES.dashboard = async (v) => {
  const { nodes, tunnels, rules, keys, events } = state.ov;
  const up = tunnels.filter((t) => t.rt.status === "up").length;
  const online = nodes.filter((n) => n.status === "online").length;
  const enabledRules = rules.filter((r) => r.rule.enabled);
  const healthy = enabledRules.filter((r) => r.rt && r.rt.probe_ok).length;
  const conns = enabledRules.reduce((a, r) => a + (r.rt ? r.rt.active : 0), 0);
  const total = rules.reduce((a, r) => a + r.total_up + r.total_down, 0);
  const sysSeries = await api("/series?key=system&range=1h");
  const last = sysSeries[sysSeries.length - 1]?.v || {};
  v.innerHTML = `
  <div class="grid stats">
    ${stat("节点在线", `${online}<small> / ${nodes.length}</small>`, nodes.length ? `待安装 ${nodes.filter((n) => n.status === "pending").length} · 离线 ${nodes.filter((n) => n.status === "offline").length}` : "尚未添加节点", nodes.length ? (online / nodes.length) * 100 : 0)}
    ${stat("WARP 隧道在线", `${up}<small> / ${tunnels.length}</small>`, tunnels.length ? `平均延迟 ${fmtMs(avg(tunnels.filter((t) => t.rt.status === "up").map((t) => t.rt.latency_ms)))}` : "尚未创建隧道", tunnels.length ? (up / tunnels.length) * 100 : 0)}
    ${stat("转发规则健康", `${healthy}<small> / ${enabledRules.length}</small>`, `共 ${rules.length} 条规则`, enabledRules.length ? (healthy / enabledRules.length) * 100 : 0)}
    ${stat("实时转发", `${fmtRate((last.fwd_up || 0) + (last.fwd_down || 0))}`, `↑ ${fmtRate(last.fwd_up || 0)} · ↓ ${fmtRate(last.fwd_down || 0)}`)}
    ${stat("活跃连接", conns, `累计转发 ${fmtBytes(total)}`)}
    ${stat("密钥池", `${keys.idle || 0}<small> 空闲</small>`, `使用中 ${keys.bound || 0} · 失效 ${keys.invalid || 0}`)}
  </div>
  <div class="grid two">
    <div class="card"><div class="card-h"><h3>转发流量（近 1 小时）</h3>${legend(trafficSeries())}</div><div class="card-b"><div id="dashChart"></div></div></div>
    <div class="card"><div class="card-h"><h3>最近事件</h3><a href="#/events" class="hint">全部 →</a></div><div class="card-b flush">${eventList(events)}</div></div>
  </div>
  <div class="card" style="margin-top:14px"><div class="card-h"><h3>节点状态</h3><a href="#/nodes" class="hint">管理 →</a></div>
    <div class="card-b flush tbl-wrap">${nodes.length ? nodeTable(nodes, false) : `<div class="empty">还没有节点。<a href="#/nodes">去添加入口 VPS →</a></div>`}</div></div>
  <div class="card" style="margin-top:14px"><div class="card-h"><h3>隧道状态</h3><a href="#/tunnels" class="hint">管理 →</a></div>
    <div class="card-b flush tbl-wrap">${tunnels.length ? `<table class="rtable"><thead><tr><th>隧道</th><th>节点</th><th>状态</th><th>出口</th><th>延迟</th><th>连接</th><th>累计收/发</th><th>握手</th></tr></thead><tbody>
    ${tunnels.map((t) => `<tr><td data-l="隧道"><b>${esc(t.name)}</b><span class="sub">${acctTag(t)}</span></td><td data-l="节点">${esc(t.node_name || "—")}</td><td data-l="状态">${pill(t.rt.status)}</td><td data-l="出口" class="mono">${esc(t.rt.egress_ip || "—")}<span class="sub">${esc(t.rt.colo || "")} ${t.rt.warp ? "warp=" + esc(t.rt.warp) : ""}</span></td><td data-l="延迟">${fmtMs(t.rt.latency_ms)}</td><td data-l="连接">${t.rt.active ?? 0}</td><td data-l="收/发">${fmtBytes(t.rt.rx)} / ${fmtBytes(t.rt.tx)}</td><td data-l="握手">${ago(t.rt.last_handshake)}</td></tr>`).join("")}
    </tbody></table>` : `<div class="empty">还没有 WARP 隧道。<a href="#/tunnels">去创建 →</a></div>`}</div></div>
  `;
  lineChart($("#dashChart"), sysSeries, trafficSeries(), { height: 220 });
};
const avg = (a) => (a.length ? a.reduce((x, y) => x + y, 0) / a.length : -1);
const trafficSeries = () => [
  { key: "fwd_down", label: "下行（目标→用户）", color: cssVar("--c2"), fmt: fmtRate, fill: true },
  { key: "fwd_up", label: "上行（用户→目标）", color: cssVar("--c1"), fmt: fmtRate, fill: true },
];
function stat(k, v, s, pct) {
  return `<div class="card stat"><div class="k">${k}</div><div class="v">${v}</div><div class="s">${s || ""}</div>${pct != null ? `<div class="bar"><i style="width:${Math.min(100, Math.max(0, pct)).toFixed(0)}%"></i></div>` : ""}</div>`;
}
const pill = (s, text) => `<span class="pill ${esc(s)}">${esc(text || STATUS[s] || s)}</span>`;
const acctTag = (t) => {
  const plus = t.account_type && t.account_type !== "free";
  return `<span class="tag ${plus ? "plus" : ""}">${plus ? "WARP+ " + esc(t.account_type) : "免费 WARP"}</span>${t.key ? ` <span class="mono">${esc(t.key)}</span>` : ""}`;
};
function eventList(evs) {
  if (!evs || !evs.length) return `<div class="empty">暂无事件</div>`;
  return `<ul class="events">${evs.map((e) => `<li><span class="lv ${esc(e.level)}"></span><time>${tstr(e.time, true)}</time><span>${esc(e.message)}</span></li>`).join("")}</ul>`;
}

// ---------- 节点 ----------
const nodeOptions = (sel) => state.ov.nodes.length
  ? state.ov.nodes.map((n) => `<option value="${esc(n.id)}" ${n.id === sel ? "selected" : ""}>${esc(n.name)}（${STATUS[n.status]}）</option>`).join("")
  : `<option value="">（还没有节点，请先到「节点」页添加）</option>`;
const nodeIP = (id) => state.ov.nodes.find((n) => n.id === id)?.ip || "";
const nodeFilterSelect = () => state.ov.nodes.length > 1
  ? `<select id="nodeFilter"><option value="">全部节点</option>${state.ov.nodes.map((n) => `<option value="${esc(n.id)}" ${n.id === state.nodeFilter ? "selected" : ""}>${esc(n.name)}</option>`).join("")}</select>` : "";
function bindNodeFilter() { const el = $("#nodeFilter"); if (el) el.onchange = () => { state.nodeFilter = el.value; render(); }; }

function nodeTable(ns, withActs) {
  return `<table class="rtable"><thead><tr><th>节点</th><th>状态</th><th>入口地址</th><th>系统</th><th>负载</th><th>隧道 / 规则</th><th>配置</th>${withActs ? "<th></th>" : ""}</tr></thead><tbody>
  ${ns.map((n) => { const sys = n.sys || {}; const synced = n.applied === n.version;
    const cdn = (n.cdn_enabled ? `<span class="tag plus" title="${esc(n.cdn_domain)}:${n.cdn_port}">CDN 出口</span> ` : "") +
      ipTag(n);
    const cdnErr = n.cdn_enabled && n.status === "online" && (!n.cdn || !n.cdn.listening) ? `<span class="sub" style="color:var(--bad)">CDN 出口未监听</span>` : "";
    return `<tr><td data-l="节点"><b>${esc(n.name)}</b><span class="sub">${cdn}${esc(n.remark || n.hostname || "")}</span>${cdnErr}</td>
    <td data-l="状态">${pill(n.status === "online" ? "up" : n.status === "offline" ? "down" : "starting", STATUS[n.status])}<span class="sub">${n.last_seen ? "同步于 " + ago(n.last_seen) : n.installed ? "已下载安装脚本" : "等待执行安装命令"}</span></td>
    <td data-l="入口地址" class="mono">${esc(n.public_host || "未设置")}<span class="sub">实际 IP ${esc(n.ip || "—")}</span></td>
    <td data-l="系统">${n.agent_version ? `Agent ${esc(n.agent_version)}<span class="sub">${esc(n.os)}/${esc(n.arch)}</span>` : "—"}</td>
    <td data-l="负载">${n.status === "online" ? `CPU ${(sys.cpu || 0).toFixed(0)}%<span class="sub">内存 ${fmtBytes(sys.mem_used)} / ${fmtBytes(sys.mem_total)}</span>` : "—"}</td>
    <td data-l="隧道 / 规则">${n.tunnels} / ${n.rules}</td>
    <td data-l="配置">${n.last_seen ? (synced ? pill("ok", "已同步") : pill("warn", "同步中")) : "—"}<span class="sub">v${n.applied || 0} / v${n.version}${n.apply_err ? ` · <span style="color:var(--bad)">${esc(n.apply_err)}</span>` : ""}</span></td>
    ${withActs ? `<td class="acts"><button class="btn sm primary" data-node="${esc(n.id)}" data-op="install">${n.installed ? "重装命令" : "安装命令"}</button><button class="btn sm" data-node="${esc(n.id)}" data-op="chart">监控</button><button class="btn sm" data-node="${esc(n.id)}" data-op="edit">编辑</button><button class="btn sm danger" data-node="${esc(n.id)}" data-op="delete">删除</button></td>` : ""}</tr>`; }).join("")}
  </tbody></table>`;
}

PAGES.nodes = async (v) => {
  const ns = state.ov.nodes;
  const base = state.ov.panel_url || location.origin;
  v.innerHTML = `
  <div class="note">每台入口 VPS 是一个节点：在这里新建节点，复制安装命令到 VPS 上用 root 执行，Agent 会自动连回面板、运行该节点的 WARP 隧道和转发规则。
    Agent 连接地址：<b class="mono">${esc(base)}</b>${base.startsWith("http://") ? `（<span style="color:var(--warn)">明文 HTTP，建议在系统设置里改成 HTTPS 域名</span>）` : ""}</div>
  <div class="toolbar"><button class="btn primary" id="newNode">＋ 新建节点</button><span class="hint grow">节点离线时 Agent 会按本地缓存的配置继续转发。</span></div>
  <div class="card"><div class="card-b flush tbl-wrap">${ns.length ? nodeTable(ns, true) : `<div class="empty">还没有节点。点击「新建节点」，然后在入口 VPS 上执行生成的安装命令。</div>`}</div></div>`;
  $("#newNode").onclick = () => nodeModal();
  $$("[data-node]", v).forEach((b) => (b.onclick = () => nodeAction(b, b.dataset.node, b.dataset.op)));
};

function nodeModal(n) {
  const edit = !!n;
  n = n || {};
  modal(`<h3>${edit ? "编辑" : "新建"}节点</h3><form id="f">
    <label>名称<input name="name" value="${esc(n.name)}" placeholder="例如：广州移动 NAT-1" maxlength="64" required></label>
    <label>入口地址（用户连接用，填入 Xboard 的节点地址）<input name="public_host" value="${esc(n.public_host)}" placeholder="建议仅 DNS（灰色云朵）的域名，如 gz1.example.com"></label>
    <label>备注<input name="remark" value="${esc(n.remark)}" maxlength="200"></label>
    <p class="hint">入口地址用域名的好处：入口机被墙或更换时只需改 DNS，Xboard 和用户订阅都不用动。该域名不能开 Cloudflare 代理，因为转发端口不在 CDN 支持范围内。</p>
    <label>CDN 优选 IP（可选，本节点作为入口走 CDN 时使用；每行一个，最多 20 个，新连接在其间轮询）<textarea name="cdn_prefer_ips" placeholder="留空则使用出口节点上的设置，再没有就按域名解析&#10;104.17.1.1&#10;104.18.2.2" style="min-height:70px">${esc((n.cdn_prefer_ips || []).join("\n"))}</textarea></label>
    ${ipStatus(n)}
    <p class="hint">优选 IP 只影响「本入口 → Cloudflare」这一段。海外入口一般留空；国内入口请在本机上测速，并用 curl --resolve 验证返回 404 后再填。</p>
    <h4 style="margin:18px 0 8px">Cloudflare CDN 出口（可选）</h4>
    <label class="check"><input type="checkbox" name="cdn_enabled" ${n.cdn_enabled ? "checked" : ""}> 让本节点作为 CDN 出口（其它节点的规则可经 Cloudflare CDN 转发到这里）</label>
    <div id="cdnBox">
      <div class="row3"><label>CDN 域名（橙色云朵，指向本节点 IP）<input name="cdn_domain" value="${esc(n.cdn_domain)}" placeholder="cdn.example.com"></label>
        <label>端口<select name="cdn_port">${[2096, 2053, 2083, 2087, 8443, 443].map((p) => `<option ${Number(n.cdn_port || 2096) === p ? "selected" : ""}>${p}</option>`).join("")}</select></label></div>
      <label>默认优选 IP（可选，每行一个；经本出口、自己没设置优选 IP 的入口使用，留空按域名解析）<textarea name="cdn_connect_ips" placeholder="104.17.1.1&#10;104.18.2.2" style="min-height:60px">${esc((n.cdn_connect_ips || []).join("\n"))}</textarea></label>
      <label>源站证书（可选，PEM。Cloudflare SSL 模式为「完全（严格）」时必填）${n.cdn_cert_info ? `<span class="sub" style="color:var(--ok)">当前：${esc(n.cdn_cert_info)}</span>` : ""}<textarea name="cdn_cert" placeholder="-----BEGIN CERTIFICATE-----（留空保持不变）" style="min-height:70px"></textarea></label>
      <label>证书私钥（PEM）<textarea name="cdn_key" placeholder="-----BEGIN PRIVATE KEY-----" style="min-height:70px"></textarea></label>
      ${n.cdn_cert_info ? `<label class="check"><input type="checkbox" name="cdn_cert_clear"> 清除已上传的证书，改用自签证书</label>` : ""}
      <p class="hint">推荐在 Cloudflare 后台「SSL/TLS → 源服务器」创建源服务器证书（免费、15 年）填到这里，这样 SSL 模式为「完全」或「完全（严格）」都能用；不填证书时出口用自签证书，只适用于「完全」或「灵活」模式。本节点防火墙需放行该端口。CDN 只转发 TCP；大流量走免费 CDN 有被 Cloudflare 限制的风险，建议作为 WARP 不可用时的备用线路。</p>
    </div>
  </form>`, async (f, btn) => {
    const body = { name: f.name.value, public_host: f.public_host.value, remark: f.remark.value, cdn_prefer_ips: ipList(f.cdn_prefer_ips.value) };
    const cdn = { cdn_enabled: f.cdn_enabled.checked, cdn_domain: f.cdn_domain.value.trim(), cdn_port: Number(f.cdn_port.value), cdn_connect_ips: ipList(f.cdn_connect_ips.value) };
    if (f.cdn_cert.value.trim() || f.cdn_key.value.trim()) { cdn.cdn_cert = f.cdn_cert.value; cdn.cdn_key = f.cdn_key.value; }
    if (f.cdn_cert_clear && f.cdn_cert_clear.checked) { cdn.cdn_cert = ""; cdn.cdn_key = ""; }
    const cdnChanged = "cdn_cert" in cdn || cdn.cdn_enabled !== !!n.cdn_enabled || (cdn.cdn_enabled && (cdn.cdn_domain !== (n.cdn_domain || "") || cdn.cdn_port !== Number(n.cdn_port || 0) || cdn.cdn_connect_ips.join() !== (n.cdn_connect_ips || []).join()));
    if (edit) return !!(await act(btn, () => api(`/nodes/${n.id}`, { method: "PATCH", body: cdnChanged ? { ...body, ...cdn } : body }), "已保存"));
    const r = await act(btn, async () => {
      const created = await api("/nodes", { method: "POST", body });
      const extra = { ...(cdn.cdn_enabled ? cdn : {}), ...(body.cdn_prefer_ips.length ? { cdn_prefer_ips: body.cdn_prefer_ips } : {}) };
      if (Object.keys(extra).length) await api(`/nodes/${created.id}`, { method: "PATCH", body: extra });
      return created;
    });
    if (r) { setTimeout(() => installModal(r), 50); return true; }
  });
  const f = $("#f"), syncCdn = () => $("#cdnBox").classList.toggle("hidden", !f.cdn_enabled.checked);
  f.cdn_enabled.onchange = syncCdn; syncCdn();
}

// 优选 IP：每行一个，也接受逗号、空格分隔
const ipList = (t) => [...new Set(t.split(/[\s,，;；]+/).map((x) => x.trim()).filter(Boolean))];

function ipTag(n) {
  const ips = n.cdn_prefer_ips || [];
  if (!ips.length) return "";
  const st = n.cdn_ips || {}, bad = ips.filter((ip) => st[ip]?.cooling).length;
  const title = ips.map((ip) => { const x = st[ip]; return x ? `${ip}  成功 ${x.ok} / 失败 ${x.fail}${x.ms ? ` / ${x.ms}ms` : ""}${x.cooling ? "（暂停中）" : ""}` : `${ip}  尚未使用`; }).join("\n");
  return `<span class="tag ${bad ? "warn" : ""}" title="${esc(title)}">优选 ${ips.length} 个 IP${bad ? `，${bad} 个暂停` : ""}</span> `;
}

function ipStatus(n) {
  const st = n.cdn_ips || {}, ips = Object.keys(st);
  if (!ips.length) return "";
  return `<div class="hint"><b>各优选 IP 状态</b>（本节点作为入口，自 Agent 启动以来）：<br>${ips.map((ip) => {
    const x = st[ip];
    return `<span class="mono">${esc(ip)}</span>：成功 ${x.ok}，失败 ${x.fail}${x.ms ? `，最近建连 ${x.ms}ms` : ""}${x.cooling ? ` <span style="color:var(--bad)">暂停中</span>` : ""}${x.error ? `<span class="sub">${esc(x.error)}</span>` : ""}`;
  }).join("<br>")}</div>`;
}

function installModal(info) {
  const base = state.ov.panel_url || location.origin;
  const url = `${base}/kw/i/${info.install_token}`;
  const cmd = `bash <(curl -fsSL '${url}' || wget -qO- '${url}')`;
  const un = `systemctl disable --now koyun-warp-agent; rm -rf /opt/koyun-warp-agent /etc/koyun-warp-agent /var/lib/koyun-warp-agent /etc/systemd/system/koyun-warp-agent.service; systemctl daemon-reload`;
  modal(`<h3>安装 Agent · ${esc(info.name)}</h3><form id="f">
    <p style="margin-top:0">在入口 VPS 上用 <b>root</b> 执行下面这一行（${new Date(info.install_expires * 1000).toLocaleTimeString()} 前有效，执行一次即可）：</p>
    <textarea readonly id="cmdBox" style="min-height:118px">${esc(cmd)}</textarea>
    <div style="display:flex;gap:8px;margin:8px 0 14px"><button class="btn primary" type="button" id="copyCmd">复制安装命令</button></div>
    <p class="hint">支持 x86_64 / ARM64 的 systemd 系统（Debian、Ubuntu、CentOS、Alma 等）。重新执行安装命令会轮换 Agent 令牌，旧令牌立即失效。</p>
    <details><summary class="hint" style="cursor:pointer">卸载命令</summary><textarea readonly style="min-height:70px;margin-top:8px">${esc(un)}</textarea></details>
  </form>`, async () => true);
  $("#mCancel").classList.add("hidden");
  $("#mOk").textContent = "完成";
  $("#copyCmd").onclick = () => { const t = $("#cmdBox"); t.select(); (navigator.clipboard ? navigator.clipboard.writeText(cmd) : Promise.reject()).then(() => toast("已复制")).catch(() => { document.execCommand("copy"); toast("已复制"); }); };
}

async function nodeAction(btn, id, op) {
  const n = state.ov.nodes.find((x) => x.id === id);
  if (!n) return;
  if (op === "edit") return nodeModal(n);
  if (op === "chart") { state.mon.key = "node:" + id; location.hash = "#/monitor"; return; }
  if (op === "install") {
    if (n.status === "online" && !confirm("该节点在线。重新生成并执行安装命令会升级 Agent 并轮换令牌，确定？")) return;
    const r = await act(btn, () => api(`/nodes/${id}/install`, { method: "POST" }));
    if (r) installModal(r);
    return;
  }
  if (op === "delete") {
    if (!confirm(`删除节点「${n.name}」？其上的 ${n.tunnels} 条隧道（远端 WARP 设备会注销）和 ${n.rules} 条规则会一并删除。VPS 上的 Agent 需另行卸载。`)) return;
    return act(btn, () => api(`/nodes/${id}`, { method: "DELETE" }), "已删除");
  }
}

// ---------- 隧道 ----------
PAGES.tunnels = async (v) => {
  const ts = state.ov.tunnels.filter((t) => !state.nodeFilter || t.node_id === state.nodeFilter);
  const idle = state.keys.filter((k) => k.status === "idle").length;
  v.innerHTML = `
  <div class="toolbar"><button class="btn primary" id="newTun">＋ 新建 WARP 隧道</button>${nodeFilterSelect()}<span class="hint grow">每条隧道是一个独立的 WARP 设备，运行在所属节点的 Agent 里，出口为 Cloudflare。空闲密钥 ${idle} 个。</span></div>
  ${ts.length ? `<div class="grid tunnels">${ts.map(tunCard).join("")}</div>` : `<div class="card"><div class="empty">还没有隧道。点击「新建 WARP 隧道」注册第一个 WARP 设备，可同时从密钥池绑定 WARP+。</div></div>`}`;
  $("#newTun").onclick = () => tunnelModal();
  bindNodeFilter();
  for (const t of ts) {
    const el = $(`#spark-${t.id}`);
    if (el) api(`/series?key=${encodeURIComponent("tunnel:" + t.id)}&range=1h`).then((pts) => lineChart(el, pts, [{ key: "latency", label: "延迟", color: cssVar("--c3") }], { compact: true, height: 44 })).catch(() => {});
  }
  $$("[data-tun]", v).forEach((b) => (b.onclick = () => tunnelAction(b, b.dataset.tun, b.dataset.op)));
};

function tunCard(t) {
  const r = t.rt;
  return `<div class="card tun">
    <div class="card-h"><h3>${esc(t.name)}<small>${esc(t.node_name || "未分配节点")}</small></h3>${pill(r.status)}</div>
    <div class="card-b">
      <div class="kv">
        <div><span>出口 IP</span><b class="mono" title="${esc(r.egress_ip)}">${esc(r.egress_ip || "—")}</b></div>
        <div><span>机房 / 模式</span><b>${esc(r.colo || "—")} · ${esc(r.warp || "—")}</b></div>
        <div><span>延迟</span><b>${fmtMs(r.latency_ms)}</b></div>
        <div><span>账户</span><b>${t.account_type && t.account_type !== "free" ? `<span class="tag plus">WARP+ ${esc(t.account_type)}</span>` : `<span class="tag">免费</span>`}</b></div>
        <div><span>密钥</span><b class="mono">${esc(t.key || "未绑定")}</b></div>
        <div><span>WARP+ 剩余额度</span><b title="Cloudflare 账户返回的 quota / premium_data">${t.key ? fmtBytes(t.quota) + (t.premium_data ? " / " + fmtBytes(t.premium_data) : "") : "—"}</b></div>
        <div><span>端点</span><b class="mono" title="${esc(t.endpoint_cfg || "默认")}">${esc(r.endpoint || t.endpoint_cfg || "默认")}</b></div>
        <div><span>最近握手</span><b>${ago(r.last_handshake)}</b></div>
        <div><span>活跃连接</span><b>${r.active ?? 0}</b></div>
        <div><span>接收</span><b>${fmtBytes(r.rx)}</b></div>
        <div><span>发送</span><b>${fmtBytes(r.tx)}</b></div>
        <div><span>运行</span><b>${r.started ? dur(Date.now() / 1000 - r.started) : "—"}</b></div>
      </div>
      ${r.error ? `<p class="err" style="margin:10px 0 0">${esc(r.error)}</p>` : ""}
      ${t.key && !t.quota && t.account_at ? `<p class="hint" style="margin:10px 0 0;color:var(--warn)">该密钥已绑定，但 Cloudflare 返回 WARP+ 额度为 0，当前按免费 WARP 线路运行。</p>` : ""}
      <div class="spark" id="spark-${esc(t.id)}"></div>
    </div>
    <div class="tun-acts">
      <button class="btn sm primary" data-tun="${esc(t.id)}" data-op="rotate">更换密钥</button>
      <button class="btn sm" data-tun="${esc(t.id)}" data-op="probe">测速</button>
      <button class="btn sm" data-tun="${esc(t.id)}" data-op="restart">重连</button>
      <button class="btn sm" data-tun="${esc(t.id)}" data-op="refresh">刷新账户</button>
      <button class="btn sm" data-tun="${esc(t.id)}" data-op="edit">编辑</button>
      <button class="btn sm" data-tun="${esc(t.id)}" data-op="reregister">重新注册</button>
      <button class="btn sm" data-tun="${esc(t.id)}" data-op="export">导出配置</button>
      <button class="btn sm" data-tun="${esc(t.id)}" data-op="toggle">${t.enabled ? "停用" : "启用"}</button>
      <button class="btn sm danger" data-tun="${esc(t.id)}" data-op="delete">删除</button>
    </div>
  </div>`;
}

function keyOptions(selected, includeNone) {
  const idle = state.keys.filter((k) => k.status === "idle");
  return (includeNone ? `<option value="">不绑定（免费 WARP）</option>` : "") +
    `<option value="auto" ${selected === "auto" ? "selected" : ""}>自动选择空闲密钥（${idle.length} 个）</option>` +
    idle.map((k) => `<option value="${esc(k.id)}">${esc(k.key)}${k.label ? " · " + esc(k.label) : ""}</option>`).join("");
}

function tunnelModal() {
  modal(`<h3>新建 WARP 隧道</h3><form id="f">
    <label>所属节点<select name="node_id" required>${nodeOptions(state.nodeFilter)}</select></label>
    <div class="row3"><label>名称<input name="name" placeholder="留空自动命名" maxlength="40"></label><label>数量<input name="count" type="number" min="1" max="10" value="1"></label></div>
    <label>WARP+ 密钥<select name="key_id">${keyOptions(state.keys.some((k) => k.status === "idle") ? "auto" : "", true)}</select></label>
    <label>端点（可选）<input name="endpoint" placeholder="留空使用全局默认，例如 162.159.192.1:2408"></label>
    <p class="hint">由控制端调用 Cloudflare 接口注册设备，再下发到节点运行（节点在国内也不受影响）。批量创建时每条隧道各占一个密钥。</p>
  </form>`, async (f, btn) => {
    if (!f.node_id.value) { toast("请先在「节点」页添加入口节点", true); return; }
    const body = { node_id: f.node_id.value, name: f.name.value.trim(), count: Number(f.count.value) || 1, key_id: f.key_id.value, endpoint: f.endpoint.value.trim() };
    const r = await act(btn, () => api("/tunnels", { method: "POST", body }));
    if (r) { toast(`已创建 ${r.created.length} 条隧道` + (r.errors.length ? `，${r.errors.length} 条失败` : "")); return true; }
  });
}

async function tunnelAction(btn, id, op) {
  const t = state.ov.tunnels.find((x) => x.id === id);
  if (!t) return;
  switch (op) {
    case "rotate":
      if (!state.keys.length) state.keys = await api("/keys");
      return modal(`<h3>更换密钥 · ${esc(t.name)}</h3><form id="f">
        <p class="hint" style="margin-top:0">当前：${t.key ? `<span class="mono">${esc(t.key)}</span>` : "未绑定"}。更换后隧道会重新握手（约 1 秒中断），新连接立即生效。</p>
        <label>新密钥<select name="key_id">${keyOptions("auto")}${t.key ? `<option value="none">释放当前密钥（回到密钥池）</option>` : ""}</select></label></form>`,
        async (f, b) => !!(await act(b, () => api(`/tunnels/${id}/rotate`, { method: "POST", body: { key_id: f.key_id.value } }), "密钥已更换")));
    case "edit":
      return modal(`<h3>编辑隧道</h3><form id="f">
        <label>名称<input name="name" value="${esc(t.name)}" maxlength="40"></label>
        <label>端点<input name="endpoint" value="${esc(t.endpoint_cfg)}" placeholder="留空使用全局默认"></label>
        <p class="hint">修改端点后隧道会立即重连。国内入口建议填写实测可用的 WARP 优选 IP:端口。</p></form>`,
        async (f, b) => !!(await act(b, () => api(`/tunnels/${id}`, { method: "PATCH", body: { name: f.name.value, endpoint: f.endpoint.value } }), "已保存")));
    case "export":
      location.href = `/kw/tunnels/${id}/wireguard`;
      return;
    case "toggle":
      return act(btn, () => api(`/tunnels/${id}`, { method: "PATCH", body: { enabled: !t.enabled } }), t.enabled ? "已停用" : "已启用");
    case "delete":
      if (!confirm(`删除隧道「${t.name}」？远端 WARP 设备也会被注销，已绑定的密钥回到密钥池。`)) return;
      return act(btn, () => api(`/tunnels/${id}`, { method: "DELETE" }), "已删除");
    case "reregister":
      if (!confirm(`为「${t.name}」重新注册 WARP 设备？内网地址和密钥对会更换，并自动重新绑定原密钥。`)) return;
      return act(btn, () => api(`/tunnels/${id}/reregister`, { method: "POST" }), "已重新注册");
    default:
      return act(btn, () => api(`/tunnels/${id}/${op}`, { method: "POST" }), { probe: "已下发测速，几秒后刷新", restart: "已下发重连", refresh: "账户信息已刷新" }[op]);
  }
}

// ---------- 密钥池 ----------
PAGES.keys = async (v) => {
  const ks = state.keys;
  const cnt = (s) => ks.filter((k) => k.status === s).length;
  v.innerHTML = `
  <div class="grid stats">${stat("密钥总数", ks.length)}${stat("空闲", cnt("idle"))}${stat("使用中", cnt("bound"))}${stat("失效", cnt("invalid"))}</div>
  <div class="grid two">
    <div class="card"><div class="card-h"><h3>密钥列表</h3></div><div class="card-b flush tbl-wrap">
      ${ks.length ? `<table class="rtable"><thead><tr><th>密钥</th><th>状态</th><th>绑定隧道</th><th>最近使用</th><th></th></tr></thead><tbody>
      ${ks.map((k) => `<tr><td data-l="密钥" class="mono">${esc(k.key)}${k.label ? `<span class="sub">${esc(k.label)}</span>` : ""}</td><td data-l="状态">${pill(k.status, KEYST[k.status])}${k.error ? `<span class="sub" style="color:var(--bad);white-space:normal;max-width:260px">${esc(k.error)}</span>` : ""}</td><td data-l="绑定隧道">${esc(k.tunnel_name || "—")}</td><td data-l="最近使用">${ago(k.last_used_at)}</td>
      <td class="acts">${k.status === "invalid" ? `<button class="btn sm" data-key="${esc(k.id)}" data-op="reset">恢复</button>` : ""}<button class="btn sm danger" data-key="${esc(k.id)}" data-op="delete" ${k.status === "bound" ? "disabled title='使用中'" : ""}>删除</button></td></tr>`).join("")}
      </tbody></table>` : `<div class="empty">密钥池为空，在右侧粘贴导入。</div>`}
    </div></div>
    <div class="card"><div class="card-h"><h3>批量导入</h3></div><div class="card-b"><form id="imp">
      <label>粘贴任意文本，自动识别 <code>xxxxxxxx-xxxxxxxx-xxxxxxxx</code> 格式的 WARP+ 密钥<textarea name="text" placeholder="🔐 Key: AbCd1234-EfGh5678-IjKl9012"></textarea></label>
      <label>标签（可选）<input name="label" placeholder="例如：2026-10 批次" maxlength="40"></label>
      <button class="btn primary" type="submit">导入</button>
    </form>
    <p class="hint" style="margin-bottom:0">一个 WARP+ 密钥最多同时绑定 5 台设备。本系统一个密钥只分配给一条隧道；密钥被回收或许可证变化时会标记失效，若开启「自动轮换」会立即换上下一个空闲密钥。</p></div></div>
  </div>`;
  $("#imp").onsubmit = async (e) => {
    e.preventDefault();
    const f = e.target, btn = $("button", f);
    const r = await act(btn, () => api("/keys", { method: "POST", body: { text: f.text.value, label: f.label.value } }));
    if (r) toast(`导入 ${r.added} 个，重复 ${r.duplicate} 个`);
  };
  $$("[data-key]", v).forEach((b) => (b.onclick = () => {
    const id = b.dataset.key;
    if (b.dataset.op === "delete") { if (confirm("删除该密钥？")) act(b, () => api(`/keys/${id}`, { method: "DELETE" }), "已删除"); }
    else act(b, () => api(`/keys/${id}/reset`, { method: "POST" }), "已恢复为空闲");
  }));
};

// ---------- 规则 ----------
PAGES.rules = async (v) => {
  const q = state.ruleQ.toLowerCase();
  const rs = state.ov.rules.filter((x) => (!state.nodeFilter || x.rule.node_id === state.nodeFilter) && (!q || [x.rule.name, x.rule.target, x.rule.listen_port, x.rule.remark, x.node_name].join(" ").toLowerCase().includes(q)));
  v.innerHTML = `
  <div class="note">用户连接 <b class="mono">入口节点地址:监听端口</b> → 该节点经 WARP 隧道（Cloudflare 出口）→ 落地节点。Xboard 中把「节点地址」改为入口地址、「连接端口」改为监听端口，节点自身端口不变。</div>
  <div class="toolbar"><button class="btn primary" id="newRule">＋ 新建转发规则</button>${nodeFilterSelect()}<input id="ruleQ" placeholder="搜索名称 / 目标 / 端口" value="${esc(state.ruleQ)}"><span class="grow"></span></div>
  <div class="card"><div class="card-b flush tbl-wrap">
  ${rs.length ? `<table class="rtable"><thead><tr><th>规则</th><th>入口 → 目标</th><th>出站</th><th title="经出站路径对目标做 TLS 握手">目标探测</th><th>连接</th><th>累计 ↑/↓</th><th></th></tr></thead><tbody>
  ${rs.map((x) => { const r = x.rule, rt = x.rt; const tn = state.ov.tunnels.find((t) => t.id === r.tunnel_id); const host = x.entry_host || nodeIP(r.node_id) || "入口地址";
    const st = !r.enabled ? pill("disabled", "已停用") : x.offline ? pill("unknown", "节点离线") : !rt ? pill("unknown", "等待同步") : rt.listen_err ? pill("down", "监听失败") : rt.probe_at === 0 ? pill("starting", "检测中") : rt.probe_ok ? (r.protocol === "udp" ? pill("up", "隧道可用") : pill("up", fmtMs(rt.probe_ms))) : pill("down", "不可达");
    return `<tr><td data-l="规则"><b>${esc(r.name)}</b><span class="sub">${esc(x.node_name || "—")} · ${esc(r.remark || PROTO[r.protocol])}</span></td>
    <td data-l="入口 → 目标" class="mono">${esc(host)}:${r.listen_port} <button class="btn sm ghost" data-copy="${esc(host)}:${r.listen_port}" title="复制">⧉</button><span class="sub">→ ${esc(r.target)}:${r.target_port}</span></td>
    <td data-l="出站">${MODE[r.mode]}${r.mode === "cdn" ? `<span class="sub">经 ${esc(state.ov.nodes.find((n) => n.id === r.cdn_exit_id)?.name || "出口已删除")}</span>` : r.mode === "tunnel" ? `<span class="sub">${esc(tn ? tn.name : "隧道已删除")}</span>` : rt && rt.probe_via ? `<span class="sub">探测经 ${esc(rt.probe_via)}</span>` : ""}</td>
    <td data-l="探测">${st}${rt && (rt.listen_err || rt.probe_err) ? `<span class="sub" style="color:var(--bad);max-width:240px;overflow:hidden;text-overflow:ellipsis" title="${esc(rt.listen_err || rt.probe_err)}">${esc(rt.listen_err || rt.probe_err)}</span>` : ""}</td>
    <td data-l="连接">${rt ? rt.active : 0}<span class="sub">失败 ${rt ? rt.failed_conns : 0} / ${rt ? rt.total_conns : 0}</span></td>
    <td data-l="累计 ↑/↓">${fmtBytes(x.total_up)} / ${fmtBytes(x.total_down)}</td>
    <td class="acts"><button class="btn sm" data-rule="${esc(r.id)}" data-op="probe">探测</button><button class="btn sm" data-rule="${esc(r.id)}" data-op="chart">图表</button><button class="btn sm" data-rule="${esc(r.id)}" data-op="edit">编辑</button><button class="btn sm" data-rule="${esc(r.id)}" data-op="${r.enabled ? "disable" : "enable"}">${r.enabled ? "停用" : "启用"}</button><button class="btn sm danger" data-rule="${esc(r.id)}" data-op="delete">删除</button></td></tr>`; }).join("")}
  </tbody></table>` : `<div class="empty">${q ? "没有匹配的规则" : "还没有转发规则。"}</div>`}
  </div></div>`;
  $("#newRule").onclick = () => ruleModal();
  bindNodeFilter();
  const qi = $("#ruleQ");
  qi.oninput = () => { state.ruleQ = qi.value; clearTimeout(qi._t); qi._t = setTimeout(() => { render().then(() => { const n = $("#ruleQ"); n.focus(); n.setSelectionRange(n.value.length, n.value.length); }); }, 250); };
  $$("[data-copy]", v).forEach((b) => (b.onclick = () => { navigator.clipboard?.writeText(b.dataset.copy).then(() => toast("已复制 " + b.dataset.copy)).catch(() => toast(b.dataset.copy)); }));
  $$("[data-rule]", v).forEach((b) => (b.onclick = () => ruleAction(b, b.dataset.rule, b.dataset.op)));
};

function ruleModal(r) {
  const edit = !!r;
  r = r || { protocol: "both", mode: "pool", listen_addr: "0.0.0.0", listen_port: "", target_port: "", node_id: state.nodeFilter };
  const tunOpts = (nid) => state.ov.tunnels.filter((t) => t.node_id === nid).map((t) => `<option value="${esc(t.id)}" ${r.tunnel_id === t.id ? "selected" : ""}>${esc(t.name)}（${STATUS[t.rt.status] || t.rt.status}）</option>`).join("") || `<option value="">（该节点暂无隧道）</option>`;
  modal(`<h3>${edit ? "编辑" : "新建"}转发规则</h3><form id="f">
    <label>入口节点<select name="node_id" required>${nodeOptions(r.node_id)}</select></label>
    <label>名称<input name="name" value="${esc(r.name)}" placeholder="例如：美西 AnyTLS 443" maxlength="64"></label>
    <div class="row3"><label>目标地址（落地节点 IP / 域名）<input name="target" value="${esc(r.target)}" required placeholder="179.255.111.112"></label><label>目标端口<input name="target_port" type="number" min="1" max="65535" value="${esc(r.target_port)}" required></label></div>
    <div class="row2"><label>监听端口<input name="listen_port" type="number" min="1" max="65535" value="${esc(r.listen_port)}" placeholder="留空自动分配"></label>
      <label>协议<select name="protocol">${Object.entries(PROTO).map(([k, v]) => `<option value="${k}" ${r.protocol === k ? "selected" : ""}>${v}</option>`).join("")}</select></label></div>
    <p class="hint">入口 IP 被墙时：监听端口填 Cloudflare 支持的端口（2053 / 2083 / 2087 / 8443 / 443），给入口机配一个<b>橙色云朵</b>域名，用户经 Cloudflare 连入口。此时落地节点必须是 WS / gRPC / HTTPUpgrade + TLS 协议，证书要对该域名有效（例如 Cloudflare 源服务器证书）。</p>
    <div class="row2"><label>出站方式<select name="mode">${Object.entries(MODE).map(([k, v]) => `<option value="${k}" ${r.mode === k ? "selected" : ""}>${v}</option>`).join("")}</select></label>
      <label id="tunWrap">隧道<select name="tunnel_id"></select></label>
      <label id="cdnWrap">CDN 出口节点<select name="cdn_exit_id">${state.ov.nodes.filter((n) => n.cdn_enabled).map((n) => `<option value="${esc(n.id)}" ${r.cdn_exit_id === n.id ? "selected" : ""}>${esc(n.name)}（${esc(n.cdn_domain)}）</option>`).join("") || `<option value="">（还没有节点开启 CDN 出口）</option>`}</select></label></div>
    <label>监听地址<input name="listen_addr" value="${esc(r.listen_addr || "0.0.0.0")}"></label>
    <label>备注<input name="remark" value="${esc(r.remark)}" maxlength="200"></label>
    <p class="hint">「WARP 隧道池」按 ${STRAT[state.ov.pool_strategy] || "系统设置"}策略在健康隧道间分配新连接，单条故障自动换下一条；「Cloudflare CDN」经开启了 CDN 出口的节点转发（仅 TCP）；海外入口到海外节点用「直连」延迟最低。Hysteria2 / TUIC 等基于 UDP 的节点请选择 UDP 或 TCP+UDP。</p>
  </form>`, async (f, btn) => {
    if (!f.node_id.value) { toast("请先在「节点」页添加入口节点", true); return; }
    const body = { node_id: f.node_id.value, name: f.name.value, target: f.target.value, target_port: Number(f.target_port.value), listen_port: Number(f.listen_port.value) || 0, protocol: f.protocol.value, mode: f.mode.value, tunnel_id: f.tunnel_id.value, cdn_exit_id: f.cdn_exit_id.value, listen_addr: f.listen_addr.value.trim(), remark: f.remark.value };
    return !!(await act(btn, () => api(edit ? `/rules/${r.id}` : "/rules", { method: edit ? "PUT" : "POST", body }), edit ? "规则已更新" : "规则已创建"));
  });
  const f = $("#f"), sync = () => {
    $("#tunWrap").classList.toggle("hidden", f.mode.value !== "tunnel");
    $("#cdnWrap").classList.toggle("hidden", f.mode.value !== "cdn");
    if (f.mode.value === "cdn") f.protocol.value = "tcp";
    [...f.protocol.options].forEach((o) => (o.disabled = f.mode.value === "cdn" && o.value !== "tcp"));
  };
  const fillTun = () => { f.tunnel_id.innerHTML = tunOpts(f.node_id.value); };
  f.mode.onchange = sync; f.node_id.onchange = fillTun; fillTun(); sync();
}

async function ruleAction(btn, id, op) {
  const x = state.ov.rules.find((y) => y.rule.id === id);
  if (!x) return;
  if (op === "edit") return ruleModal(x.rule);
  if (op === "chart") { state.mon.key = "rule:" + id; location.hash = "#/monitor"; return; }
  if (op === "delete") { if (!confirm(`删除规则「${x.rule.name}」？正在进行的连接会断开。`)) return; return act(btn, () => api(`/rules/${id}`, { method: "DELETE" }), "已删除"); }
  if (op === "probe") {
    const r = await act(btn, () => api(`/rules/${id}/probe`, { method: "POST" }));
    setTimeout(() => refresh(true), 4000);
    if (r) toast("已下发探测，节点几秒后回报结果");
    return;
  }
  return act(btn, () => api(`/rules/${id}/${op}`, { method: "POST" }), op === "enable" ? "已启用" : "已停用");
}

// ---------- 监控 ----------
PAGES.monitor = async (v) => {
  const { tunnels, rules, nodes } = state.ov;
  const m = state.mon;
  const opts = [`<option value="system">全部节点汇总</option>`]
    .concat(nodes.map((n) => `<option value="node:${esc(n.id)}">节点 · ${esc(n.name)}</option>`))
    .concat(tunnels.map((t) => `<option value="tunnel:${esc(t.id)}">隧道 · ${esc(t.name)}</option>`))
    .concat(rules.map((r) => `<option value="rule:${esc(r.rule.id)}">规则 · ${esc(r.rule.name)}</option>`));
  if (!opts.some((o) => o.includes(`"${m.key}"`))) m.key = "system";
  const pts = await api(`/series?key=${encodeURIComponent(m.key)}&range=${m.range}`);
  const step = m.range === "24h" ? 300 : 10;
  const charts = [];
  if (m.key === "system") {
    charts.push(["转发流量（全部节点）", trafficSeries()], ["活跃连接（全部节点）", [{ key: "conns", label: "连接数", color: cssVar("--c4"), fmt: (v) => v.toFixed(0), fill: true }]]);
  } else if (m.key.startsWith("node:")) {
    charts.push(["转发流量", trafficSeries()], ["活跃连接", [{ key: "conns", label: "连接数", color: cssVar("--c4"), fmt: (v) => v.toFixed(0), fill: true }]],
      ["网卡吞吐", [{ key: "rx", label: "接收", color: cssVar("--c2"), fmt: fmtRate }, { key: "tx", label: "发送", color: cssVar("--c1"), fmt: fmtRate }]],
      ["CPU", [{ key: "cpu", label: "CPU %", color: cssVar("--c5"), fmt: (v) => v.toFixed(0) + "%", fill: true }]],
      ["内存", [{ key: "mem", label: "已用内存", color: cssVar("--c3"), fmt: fmtBytes, fill: true }]]);
  } else if (m.key.startsWith("tunnel:")) {
    charts.push(["隧道延迟（经 WARP 到 1.1.1.1:443）", [{ key: "latency", label: "延迟", color: cssVar("--c3"), fmt: fmtMs, fill: true }]],
      ["隧道吞吐", [{ key: "rx", label: "接收", color: cssVar("--c2"), fmt: fmtRate, fill: true }, { key: "tx", label: "发送", color: cssVar("--c1"), fmt: fmtRate, fill: true }]],
      ["活跃连接", [{ key: "conns", label: "连接数", color: cssVar("--c4"), fmt: (v) => v.toFixed(0) }]]);
  } else {
    charts.push(["目标探测延迟（含 WARP 路径）", [{ key: "latency", label: "TCP 建连", color: cssVar("--c3"), fmt: fmtMs, fill: true }]],
      ["规则流量", trafficSeries().map((s) => ({ ...s, key: s.key.replace("fwd_", "") }))],
      ["活跃连接", [{ key: "conns", label: "连接数", color: cssVar("--c4"), fmt: (v) => v.toFixed(0), fill: true }]]);
  }
  const lat = pts.map((p) => p.v.latency).filter((x) => x != null);
  const okLat = lat.filter((x) => x >= 0);
  const loss = lat.length ? ((lat.length - okLat.length) / lat.length) * 100 : null;
  v.innerHTML = `
  <div class="toolbar"><select id="monKey">${opts.join("")}</select>
    <div class="seg"><button data-r="1h" class="${m.range === "1h" ? "on" : ""}">1 小时</button><button data-r="24h" class="${m.range === "24h" ? "on" : ""}">24 小时</button></div>
    <span class="grow"></span><span class="hint">${pts.length} 个采样点 · ${m.range === "1h" ? "10 秒" : "5 分钟平均"}粒度</span></div>
  ${lat.length ? `<div class="grid stats">${stat("平均延迟", fmtMs(avg(okLat)))}${stat("最低 / 最高", `${fmtMs(Math.min(...okLat))} <small>/ ${fmtMs(Math.max(...okLat))}</small>`)}${stat("探测失败率", loss.toFixed(1) + "<small>%</small>", `${lat.length - okLat.length} / ${lat.length} 次失败`)}${stat("抖动", fmtMs(jitter(okLat)), "相邻采样差值平均")}</div>` : ""}
  <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(min(100%,520px),1fr))">
    ${charts.map((c, i) => `<div class="card"><div class="card-h"><h3>${c[0]}</h3>${legend(c[1])}</div><div class="card-b"><div id="mc${i}"></div></div></div>`).join("")}
  </div>
  ${m.key === "system" && tunnels.length ? `<div class="card" style="margin-top:14px"><div class="card-h"><h3>隧道延迟对比</h3>${legend(tunnels.map((t, i) => ({ label: t.name, color: cssVar("--c" + ((i % 5) + 1)) })))}</div><div class="card-b"><div id="cmp"></div></div></div>` : ""}`;
  charts.forEach((c, i) => lineChart($("#mc" + i), pts, c[1], { height: 200, range: m.range, step }));
  $("#monKey").value = m.key;
  $("#monKey").onchange = (e) => { m.key = e.target.value; render(); };
  $$(".seg button", v).forEach((b) => (b.onclick = () => { m.range = b.dataset.r; render(); }));
  if ($("#cmp")) {
    const all = await Promise.all(tunnels.map((t) => api(`/series?key=${encodeURIComponent("tunnel:" + t.id)}&range=${m.range}`)));
    const merged = new Map();
    all.forEach((ps, i) => ps.forEach((p) => { if (p.v.latency == null) return; const e = merged.get(p.t) || { t: p.t, v: {} }; e.v["t" + i] = p.v.latency; merged.set(p.t, e); }));
    lineChart($("#cmp"), [...merged.values()].sort((a, b) => a.t - b.t), tunnels.map((t, i) => ({ key: "t" + i, label: t.name, color: cssVar("--c" + ((i % 5) + 1)), fmt: fmtMs })), { height: 220, range: m.range, step: m.range === "24h" ? 300 : 30 });
  }
};
const jitter = (a) => { if (a.length < 2) return -1; let s = 0; for (let i = 1; i < a.length; i++) s += Math.abs(a[i] - a[i - 1]); return s / (a.length - 1); };

// ---------- 事件 ----------
PAGES.events = async (v) => {
  const f = state.evFilter;
  const evs = (state.events || []).filter((e) => !f || e.level === f);
  v.innerHTML = `<div class="toolbar"><div class="seg">${[["", "全部"], ["error", "错误"], ["warn", "警告"], ["info", "信息"]].map(([k, l]) => `<button data-f="${k}" class="${f === k ? "on" : ""}">${l}</button>`).join("")}</div><span class="hint">保留最近 500 条；警告和错误会推送到 Telegram（如已配置）。</span></div>
  <div class="card"><div class="card-b flush">${eventList(evs)}</div></div>`;
  $$(".seg button", v).forEach((b) => (b.onclick = () => { state.evFilter = b.dataset.f; render(); }));
};

// ---------- 设置 ----------
PAGES.settings = async (v) => {
  if (!state.settings) state.settings = await api("/settings");
  const s = state.settings;
  v.innerHTML = `<div class="grid two">
  <div class="card"><div class="card-h"><h3>转发与隧道</h3></div><div class="card-b"><form id="sf">
    <label>Agent 连接地址（安装命令里使用，建议填开了 Cloudflare 代理的面板域名）<input name="panel_url" value="${esc(s.panel_url)}" placeholder="${esc(location.origin)}"></label>
    <label>默认 WARP 端点<input name="default_endpoint" value="${esc(s.default_endpoint)}"></label>
    <div class="row2"><label>MTU<input name="mtu" type="number" value="${s.mtu}"></label><label>隧道池策略<select name="pool_strategy">${Object.entries(STRAT).map(([k, l]) => `<option value="${k}" ${s.pool_strategy === k ? "selected" : ""}>${l}</option>`).join("")}</select></label></div>
    <div class="row2"><label>探测间隔（秒）<input name="probe_interval" type="number" value="${s.probe_interval}"></label><label>连续失败几次后重建隧道<input name="fail_threshold" type="number" value="${s.fail_threshold}"></label></div>
    <div class="row2"><label>监听端口下限<input name="port_min" type="number" value="${s.port_min}"></label><label>监听端口上限<input name="port_max" type="number" value="${s.port_max}"></label></div>
    <label class="check"><input type="checkbox" name="auto_rotate" ${s.auto_rotate ? "checked" : ""}> 密钥失效时自动从密钥池换下一个</label>
    <h4 style="margin:18px 0 10px">Telegram 告警</h4>
    <div class="row2"><label>Bot Token<input name="telegram_token" value="${esc(s.telegram_token)}" placeholder="123456:ABC…"></label><label>Chat ID<input name="telegram_chat" value="${esc(s.telegram_chat)}"></label></div>
    <div style="display:flex;gap:8px"><button class="btn primary" type="submit">保存设置</button><button class="btn" type="button" id="tgTest">发送测试通知</button></div>
  </form></div></div>
  <div class="card"><div class="card-h"><h3>管理员</h3></div><div class="card-b"><form id="pf">
    <label>用户名<input name="username" value="${esc(s.admin_user)}" autocomplete="username"></label>
    <label>原密码<input name="old" type="password" autocomplete="current-password" required></label>
    <label>新密码（至少 10 位）<input name="new" type="password" autocomplete="new-password" minlength="10" required></label>
    <button class="btn primary" type="submit">修改凭据</button></form>
    <p class="hint">修改后其它已登录的会话全部失效。忘记密码可在服务器执行 <code>koyun-warp -reset-password</code>。</p></div></div>
  </div>`;
  $("#sf").onsubmit = async (e) => {
    e.preventDefault();
    const f = e.target, num = (n) => Number(f[n].value);
    const body = { panel_url: f.panel_url.value.trim(), default_endpoint: f.default_endpoint.value, mtu: num("mtu"), pool_strategy: f.pool_strategy.value, probe_interval: num("probe_interval"), fail_threshold: num("fail_threshold"), port_min: num("port_min"), port_max: num("port_max"), auto_rotate: f.auto_rotate.checked, telegram_token: f.telegram_token.value.trim(), telegram_chat: f.telegram_chat.value };
    if (await act($("button[type=submit]", f), () => api("/settings", { method: "PUT", body }), "设置已保存")) state.settings = await api("/settings");
  };
  $("#tgTest").onclick = (e) => act(e.target, () => api("/notify-test", { method: "POST" }), "测试通知已发送");
  $("#pf").onsubmit = async (e) => {
    e.preventDefault();
    const f = e.target;
    if (await act($("button", f), () => api("/password", { method: "POST", body: { username: f.username.value, old: f.old.value, new: f.new.value } }), "凭据已修改")) { f.old.value = f.new.value = ""; state.settings = null; }
  };
};

// ---------- 弹窗 ----------
function modal(html, onOk) {
  const m = $("#modal"), c = $("#modalCard");
  c.innerHTML = html + `<div class="modal-foot"><button class="btn" id="mCancel" type="button">取消</button><button class="btn primary" id="mOk" type="button">确定</button></div>`;
  m.classList.remove("hidden");
  const close = () => m.classList.add("hidden");
  const f = $("#f", c);
  const submit = async () => {
    if (f && !f.reportValidity()) return;
    if (await onOk(f, $("#mOk"))) close();
  };
  $("#mCancel").onclick = close;
  $("#mOk").onclick = submit;
  if (f) f.onsubmit = (e) => { e.preventDefault(); submit(); };
  m.onclick = (e) => { if (e.target === m) close(); };
  document.onkeydown = (e) => { if (e.key === "Escape") close(); };
  setTimeout(() => $("input, select", c)?.focus(), 30);
}

// ---------- 启动 ----------
api("/me").then((r) => start(r.user)).catch(() => showLogin());
