const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';

const SER = [
  { id: 'gw', name: 'Gateway', short: 'GW', targetId: 1, target: '192.168.1.1' },
  { id: 'icmp', name: 'WAN ICMP', short: 'ICMP', targetId: 10, target: '1.1.1.1' },
  { id: 'tcp', name: 'WAN TCP', short: 'TCP', targetId: 20, target: '1.1.1.1:443' },
  { id: 'dns', name: 'DNS', short: 'DNS', targetId: 30, target: '1.1.1.1:53' },
  { id: 'http', name: 'HTTP 204', short: 'HTTP', targetId: 50, target: 'cp.cloudflare.com' }
];

const BYID = {};
SER.forEach(s => { BYID[s.id] = s; });

const CLS = {
  wan: { label: 'ISP / WAN drop', sev: 'bad', fail: ['icmp', 'tcp', 'dns', 'http'], gw: true },
  dns: { label: 'DNS timeout', sev: 'bad', fail: ['dns'], gw: true },
  local: { label: 'Local Wi-Fi / gateway', sev: 'bad', fail: ['gw', 'icmp', 'tcp', 'dns', 'http'], gw: false },
  http: { label: 'HTTP timeout', sev: 'warn', fail: ['http'], gw: true },
  lat: { label: 'High latency', sev: 'warn', fail: [], gw: true }
};

const ERR = {
  gw: 'no echo reply (1000 ms)',
  icmp: 'request timed out (1000 ms)',
  tcp: 'dial tcp: i/o timeout (1200 ms)',
  dns: 'no response from 1.1.1.1:53 (1200 ms)',
  http: 'context deadline exceeded (2000 ms)'
};

const STAGGER = { gw: 0, icmp: 0, dns: 250, tcp: 500, http: 750 };
const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const DOW = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const RANGE = { '15m': 9e5, '1h': 36e5, '24h': 864e5, '7d': 6048e5 };

const ICO = {
  check: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M3 8.5l3.2 3.2L13 4.8" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  x: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M4 4l8 8M12 4l-8 8" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
  warn: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 2l6.5 11.5h-13z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M8 6.5v3M8 11.3v.4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>'
};

const BADGE = {
  healthy: ['HEALTHY', 'check'],
  degraded: ['DEGRADED', 'warn'],
  recovering: ['RECOVERING', 'warn'],
  outage: ['OUTAGE', 'x'],
  paused: ['PAUSED', 'warn'],
  suspended: ['SUSPENDED', 'warn']
};

let live = [];
let backendState = '';
let events = [];
let failedSamples = [];
let hover = null;
let paused = false;
let currentGatewayIP = '192.168.1.1';
let currentInterface = 'Ethernet';

const F = { mode: 'out', proto: 'all', cls: 'all', range: '7d', limit: 10 };

function $(id) {
  return document.getElementById(id);
}

function pad(n) {
  return String(n).padStart(2, '0');
}

function fmtT(ts, ms) {
  const d = new Date(ts);
  return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()) + (ms ? '.' + String(d.getMilliseconds()).padStart(3, '0') : '');
}

function fmtD(ts) {
  const d = new Date(ts);
  return MON[d.getMonth()] + ' ' + d.getDate();
}

function fmtDur(ms) {
  return (ms / 1000).toFixed(1) + ' s';
}

function fmtAgo(ms) {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return s + ' s';
  const m = Math.floor(s / 60);
  if (m < 60) return m + ' min';
  const h = Math.floor(m / 60);
  if (h < 48) return h + ' h ' + (m % 60) + ' min';
  return Math.floor(h / 24) + ' d';
}

function mapClassification(raw) {
  const c = String(raw || '').toUpperCase();
  if (c.includes('GATEWAY') || c.includes('LINK_DOWN')) return 'local';
  if (c.includes('DNS')) return 'dns';
  if (c.includes('HTTP') || c.includes('CAPTIVE')) return 'http';
  if (c.includes('LATENCY')) return 'lat';
  return 'wan';
}

function normalizeEvent(e) {
  const cls = mapClassification(e.classification);
  const dur = e.duration_ms != null ? e.duration_ms : (e.end_ms ? e.end_ms - e.start_ms : 0);
  return {
    id: e.id,
    start: e.start_ms,
    dur: Math.max(100, dur),
    cls: cls,
    gwRtt: e.gateway_ok_pct != null && e.gateway_ok_pct > 0 ? 1.8 : 0,
    raw: e
  };
}

function calcState() {
  if (paused) return 'paused';
  if (backendState && backendState !== 'suspended') return backendState;
  if (!live.length) return 'healthy';
  const last = live[live.length - 1];
  const wanDown = last.v.icmp == null && last.v.tcp == null;
  const gwDown = last.v.gw == null;
  if (wanDown || gwDown) {
    const prev = live.length > 1 ? live[live.length - 2] : null;
    if (prev && ((prev.v.icmp == null && prev.v.tcp == null) || prev.v.gw == null)) {
      return 'outage';
    }
    return 'degraded';
  }
  const anyBad = SER.some(s => last.v[s.id] == null);
  if (anyBad) return 'degraded';
  return 'healthy';
}

function computeStats(win) {
  const now = Date.now();
  const ev = events.filter(e => e.start > (now - win) && e.cls !== 'lat');
  const down = ev.reduce((a, e) => a + e.dur, 0) / 1000;
  const totalSec = win / 1000;
  const up = Math.max(0, Math.min(100, 100 * (1 - (down / totalSec))));
  const max = ev.reduce((a, e) => Math.max(a, e.dur), 0) / 1000;
  return { n: ev.length, down: down, up: up, max: max };
}

function renderStatus() {
  const st = calcState();
  const b = $('badge');
  if (!b) return;

  const conf = BADGE[st] || BADGE.healthy;
  b.dataset.state = st;
  b.innerHTML = ICO[conf[1]] + '<span>' + conf[0] + '</span>';

  const lastClosed = events.filter(e => e.cls !== 'lat')[0];
  let txt = '';
  if (st === 'outage') {
    txt = 'Nothing is answering from the internet. NetScan is probing every <strong>500 ms</strong> to time the drop.';
  } else if (st === 'degraded') {
    txt = 'One probe failed. NetScan waits for a second failure before it calls this an outage.';
  } else if (st === 'recovering') {
    txt = 'Answers are coming back. The drop is closed after <strong>3 good probes</strong> in a row.';
  } else if (st === 'suspended') {
    txt = 'System sleep or gap detected. Re-evaluating connection stability.';
  } else if (st === 'paused') {
    txt = 'Monitoring paused. Background probing is temporarily halted.';
  } else if (lastClosed) {
    const c = CLS[lastClosed.cls] || CLS.wan;
    const ago = fmtAgo(Date.now() - (lastClosed.start + lastClosed.dur));
    txt = 'Connected. Last drop <strong>' + ago + ' ago</strong>, lasted ' + fmtDur(lastClosed.dur) + ' (' + c.label + '). ' +
      (c.gw ? 'Your router kept answering, so the problem was upstream.' : 'Your router stopped answering too.');
  } else {
    txt = 'Connected and monitoring all network layers. No recent outage events recorded.';
  }
  $('status-text').innerHTML = txt;

  const a = computeStats(864e5);
  const w = computeStats(6048e5);
  $('stats').innerHTML =
    '<div class="stat"><dt>Uptime</dt><dd class="big">' + a.up.toFixed(2) + '%</dd><dd class="sub">24 h &middot; <b>' + w.up.toFixed(2) + '%</b> over 7 d</dd></div>' +
    '<div class="stat"><dt>Drops</dt><dd class="big">' + a.n + '</dd><dd class="sub">24 h &middot; <b>' + w.n + '</b> over 7 d</dd></div>' +
    '<div class="stat"><dt>Time offline</dt><dd class="big">' + Math.round(a.down) + ' s</dd><dd class="sub">24 h &middot; <b>' + Math.round(w.down) + ' s</b> over 7 d</dd></div>' +
    '<div class="stat"><dt>Longest drop</dt><dd class="big">' + a.max.toFixed(1) + ' s</dd><dd class="sub">24 h &middot; <b>' + w.max.toFixed(1) + ' s</b> over 7 d</dd></div>';
}

function pathD(vals, x, y) {
  let d = '';
  let pen = false;
  vals.forEach((v, i) => {
    if (v == null) {
      pen = false;
      return;
    }
    d += (pen ? 'L' : 'M') + x(i).toFixed(1) + ' ' + y(v).toFixed(1);
    pen = true;
  });
  return d;
}

function renderTiles() {
  const container = $('tiles');
  if (!container) return;

  container.innerHTML = SER.map(s => {
    const vals = live.map(p => p.v[s.id]);
    const last = vals.length ? vals[vals.length - 1] : null;
    const ok = vals.filter(v => v != null);
    const avg = ok.length ? ok.reduce((a, b) => a + b, 0) / ok.length : 0;
    const loss = vals.length ? 100 * (vals.length - ok.length) / vals.length : 0;
    const mx = Math.max.apply(null, ok.concat([10]));
    const W = 200;
    const H = 32;
    const x = i => 2 + i * (W - 8) / Math.max(1, vals.length - 1);
    const y = v => H - 3 - (v / mx) * (H - 8);
    const d = pathD(vals, x, y);
    const fails = vals.map((v, i) => v == null ? '<line class="fail-tick" x1="' + x(i).toFixed(1) + '" x2="' + x(i).toFixed(1) + '" y1="' + (H - 8) + '" y2="' + (H - 1) + '"/>' : '').join('');
    const lastOk = last != null;
    const ex = x(vals.length - 1);
    const spark = '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" aria-hidden="true"><path class="ln" style="stroke-width:1.6" d="' + d + '" vector-effect="non-scaling-stroke"/>' + fails + (lastOk ? '<circle class="dot" cx="' + ex.toFixed(1) + '" cy="' + y(last).toFixed(1) + '" r="3"/>' : '') + '</svg>';

    return '<div class="tile card c-' + s.id + '"><div class="tile-h"><span class="tile-n"><i class="sw"></i>' + s.name + '</span>' +
      (lastOk ? '<span class="pill good">' + ICO.check + 'OK</span>' : '<span class="pill bad">' + ICO.x + 'Timeout</span>') + '</div>' +
      '<div class="tile-t">' + s.target + '</div>' +
      '<div class="tile-v">' + (lastOk ? '<b>' + last.toFixed(1) + '</b><span>ms</span>' : '<b class="bad">no answer</b>') + '</div>' + spark +
      '<div class="tile-f"><span>60 s avg <b>' + avg.toFixed(1) + ' ms</b></span><span>loss <b>' + loss.toFixed(1) + '%</b></span></div></div>';
  }).join('');
}

const CW = 960;
const CH = 300;
const CL = 44;
const CR = 16;
const CT = 12;
const CB = 28;
const YMAX = 120;

function cx(i) {
  return CL + i * (CW - CL - CR) / Math.max(1, live.length - 1);
}

function cy(v) {
  return CT + (1 - Math.min(v, YMAX) / YMAX) * (CH - CT - CB);
}

function renderChart() {
  const chartEl = $('chart');
  if (!chartEl) return;
  const n = live.length;
  if (!n) return;
  const step = (CW - CL - CR) / Math.max(1, n - 1);
  let g = '';

  [0, 30, 60, 90, 120].forEach(t => {
    g += '<line class="grid" x1="' + CL + '" x2="' + (CW - CR) + '" y1="' + cy(t) + '" y2="' + cy(t) + '"/><text x="' + (CL - 8) + '" y="' + (cy(t) + 4) + '" text-anchor="end">' + t + '</text>';
  });
  [0, 15, 30, 45, 59].forEach((k, j) => {
    g += '<text x="' + cx(k) + '" y="' + (CH - 8) + '" text-anchor="' + (k === 0 ? 'start' : k === 59 ? 'end' : 'middle') + '">' + ['-60 s', '-45 s', '-30 s', '-15 s', 'now'][j] + '</text>';
  });
  g += '<text x="' + (CL - 8) + '" y="' + (CH - 8) + '" text-anchor="end" style="font-size:10px">ms</text>';

  const wan = live.map(p => p.v.icmp == null && p.v.tcp == null);
  let bands = '';
  const inWan = new Array(n);
  for (let i = 0; i < n; i++) {
    if (wan[i]) {
      let j = i;
      while (j + 1 < n && wan[j + 1]) j++;
      for (let q = i; q <= j; q++) inWan[q] = true;
      const x0 = Math.max(CL, cx(i) - step / 2);
      const x1 = Math.min(CW - CR, cx(j) + step / 2);
      bands += '<rect class="band-bad" x="' + x0.toFixed(1) + '" y="' + CT + '" width="' + (x1 - x0).toFixed(1) + '" height="' + (CH - CT - CB) + '"/>' + (x1 - x0 > 46 ? '<text class="band-lbl" x="' + ((x0 + x1) / 2).toFixed(1) + '" y="' + (CT + 14) + '" text-anchor="middle">timeout</text>' : '');
      i = j;
    }
  }

  let lines = '';
  const order = ['icmp', 'tcp', 'dns', 'http', 'gw'];
  order.forEach(id => {
    const vals = live.map(p => p.v[id]);
    lines += '<g class="c-' + id + '"><path class="ln" d="' + pathD(vals, cx, cy) + '"/>' +
      '<circle class="dot" cx="' + cx(n - 1) + '" cy="' + (vals[n - 1] != null ? cy(vals[n - 1]) : CH - CB) + '" r="4" style="' + (vals[n - 1] == null ? 'display:none' : '') + '"/></g>';
  });

  let ticks = '';
  for (let i = 0; i < n; i++) {
    if (!inWan[i]) {
      SER.forEach((s, k) => {
        if (live[i].v[s.id] == null) {
          ticks += '<line class="fail-tick" x1="' + (cx(i) + (k - 2) * 2.5).toFixed(1) + '" x2="' + (cx(i) + (k - 2) * 2.5).toFixed(1) + '" y1="' + (CH - CB - 9) + '" y2="' + (CH - CB - 1) + '"/>';
        }
      });
    }
  }

  const xh = hover != null ? '<line class="xhair" x1="' + cx(hover) + '" x2="' + cx(hover) + '" y1="' + CT + '" y2="' + (CH - CB) + '"/>' : '';
  chartEl.innerHTML = '<svg class="plot" id="plot" viewBox="0 0 ' + CW + ' ' + CH + '" role="img" aria-label="Round-trip time for each probe over the last 60 seconds">' + g + bands + '<line class="axis" x1="' + CL + '" x2="' + (CW - CR) + '" y1="' + (CH - CB) + '" y2="' + (CH - CB) + '"/>' + lines + ticks + xh + '</svg>';

  const p = live[hover != null ? hover : n - 1];
  $('legend').innerHTML = SER.map(s => {
    const v = p.v[s.id];
    return '<span class="c-' + s.id + '"><i></i>' + s.name + ' <b>' + (v == null ? 'timeout' : v.toFixed(1) + ' ms') + '</b></span>';
  }).join('') + '<span class="at">' + (hover != null ? fmtT(p.ts, true) : 'live') + '</span>';
}

const HW = 960;
const HL = 84;
const HT = 22;
const HR = 8;
const ROWH = 22;
const ROWG = 4;
const NB = 96;
const CELL = (HW - HL - HR) / NB;
const HH = HT + 7 * (ROWH + ROWG);
let BUCKET = [];

function buildHeatmapBuckets() {
  const now = Date.now();
  const d0 = new Date(now);
  d0.setHours(0, 0, 0, 0);
  const mid = d0.getTime();
  BUCKET = [];

  for (let row = 0; row < 7; row++) {
    const ds = mid - (6 - row) * 864e5;
    BUCKET.push([]);
    for (let b = 0; b < NB; b++) {
      const a = ds + b * 9e5;
      const z = a + 9e5;
      if (a > now) {
        BUCKET[row].push(null);
        continue;
      }
      const evs = [];
      let loss = 0;
      events.forEach(e => {
        if (e.cls === 'lat') return;
        const o = Math.min(z, e.start + e.dur) - Math.max(a, e.start);
        if (o > 0) {
          loss += o / 9e3;
          evs.push(e);
        }
      });
      BUCKET[row].push({ a: a, z: z, loss: Math.min(100, loss), evs: evs });
    }
  }
}

function lvl(l) {
  return l <= 0 ? 0 : l < 0.2 ? 1 : l < 0.5 ? 2 : l < 1 ? 3 : 4;
}

function renderHeat() {
  buildHeatmapBuckets();
  const heatEl = $('heat');
  if (!heatEl) return;
  const d0 = new Date(Date.now());
  d0.setHours(0, 0, 0, 0);
  const mid = d0.getTime();
  let s = '';

  [0, 6, 12, 18, 24].forEach(h => {
    const x = HL + h * 4 * CELL;
    s += '<text x="' + x.toFixed(1) + '" y="12" text-anchor="' + (h === 0 ? 'start' : h === 24 ? 'end' : 'middle') + '">' + pad(h % 24) + ':00</text>';
  });

  for (let row = 0; row < 7; row++) {
    const ds = mid - (6 - row) * 864e5;
    const d = new Date(ds);
    const y = HT + row * (ROWH + ROWG);
    s += '<text x="' + (HL - 10) + '" y="' + (y + 15) + '" text-anchor="' + 'end' + '">' + (row === 6 ? 'Today' : DOW[d.getDay()] + ' ' + MON[d.getMonth()] + ' ' + d.getDate()) + '</text>';
    for (let b = 0; b < NB; b++) {
      const c = BUCKET[row][b];
      const x = HL + b * CELL;
      if (!c) {
        s += '<rect x="' + (x + 0.5).toFixed(2) + '" y="' + y + '" width="' + (CELL - 1).toFixed(2) + '" height="' + ROWH + '" fill="none" stroke="var(--line-2)" stroke-width="1"/>';
        continue;
      }
      s += '<rect x="' + (x + 0.5).toFixed(2) + '" y="' + y + '" width="' + (CELL - 1).toFixed(2) + '" height="' + ROWH + '" fill="var(--seq' + lvl(c.loss) + ')"/>';
    }
  }

  events.forEach(e => {
    if (e.cls === 'lat') return;
    const row = Math.floor((e.start - (mid - 6 * 864e5)) / 864e5);
    if (row < 0 || row > 6) return;
    const x = HL + ((e.start - (mid - (6 - row) * 864e5)) / 864e5) * (NB * CELL);
    const y = HT + row * (ROWH + ROWG);
    s += '<rect x="' + (x - 1).toFixed(1) + '" y="' + (y - 3) + '" width="2.5" height="' + (ROWH + 6) + '" fill="var(--bad)" rx="1"/>';
  });

  s += '<rect id="hl" x="0" y="0" width="0" height="0" fill="none" stroke="var(--ink)" stroke-width="1.5" pointer-events="none"/>';
  heatEl.innerHTML = '<svg class="plot" id="hsvg" viewBox="0 0 ' + HW + ' ' + HH + '" role="img" aria-label="Packet loss for each 15 minute block over the last 7 days">' + s + '</svg>';
}

function heatAt(e) {
  const hsvg = $('hsvg');
  if (!hsvg) return null;
  const b = hsvg.getBoundingClientRect();
  const vx = (e.clientX - b.left) / b.width * HW;
  const vy = (e.clientY - b.top) / b.height * HH;
  const col = Math.floor((vx - HL) / CELL);
  const row = Math.floor((vy - HT) / (ROWH + ROWG));
  if (col < 0 || col >= NB || row < 0 || row > 6 || ((vy - HT) % (ROWH + ROWG)) > ROWH) return null;
  return { row: row, col: col, c: BUCKET[row][col] };
}

function filteredEvents() {
  const now = Date.now();
  const w = RANGE[F.range] || RANGE['7d'];
  return events.filter(e => {
    if (now - e.start > w) return false;
    if (F.proto !== 'all' && !(CLS[e.cls].fail.includes(F.proto))) return false;
    if (F.cls !== 'all' && e.cls !== F.cls) return false;
    return true;
  });
}

function filteredFailedProbes() {
  const now = Date.now();
  const w = RANGE[F.range] || RANGE['7d'];
  return failedSamples.filter(p => {
    if (now - p.ts > w) return false;
    if (F.proto !== 'all' && p.proto !== F.proto) return false;
    if (F.cls !== 'all' && p.cls !== F.cls) return false;
    return true;
  });
}

function chip(id) {
  const item = BYID[id] || { short: id.toUpperCase() };
  return '<span class="chip c-' + id + '"><i></i>' + item.short + '</span>';
}

function renderLog() {
  const out = F.mode === 'out';
  const rows = out ? filteredEvents() : filteredFailedProbes();
  const shown = rows.slice(0, F.limit);

  $('log-count').textContent = rows.length + (out ? ' outage events' : ' failed probes') + ' in selected range';
  $('thead').innerHTML = out
    ? '<tr><th>Time</th><th>Length</th><th>Cause</th><th>Router</th><th>Failed probes</th></tr>'
    : '<tr><th>Time</th><th>Probe</th><th>Target</th><th>Error</th><th>Cause</th></tr>';

  if (!shown.length) {
    $('tbody').innerHTML = '<tr><td colspan="5" class="empty">No drops match these filters. Try a longer time range.</td></tr>';
  } else {
    $('tbody').innerHTML = shown.map(e => {
      if (out) {
        const c = CLS[e.cls] || CLS.wan;
        return '<tr data-id="' + e.id + '"><td><button class="rowbtn" type="button" data-id="' + e.id + '">' + fmtD(e.start) + ' ' + fmtT(e.start) + '</button></td><td class="mono">' + fmtDur(e.dur) + '</td>' +
          '<td><span class="pill ' + c.sev + '">' + (c.sev === 'bad' ? ICO.x : ICO.warn) + c.label + '</span></td>' +
          '<td>' + (c.gw ? '<span class="gwc ok">' + ICO.check + '<span class="mono">' + e.gwRtt.toFixed(1) + ' ms</span></span>' : '<span class="gwc no">' + ICO.x + 'No reply</span>') + '</td>' +
          '<td>' + (c.fail.length ? '<div class="chips">' + c.fail.map(chip).join('') + '</div>' : '<span class="muted">All answered, RTT above 400 ms</span>') + '</td></tr>';
      }
      const c2 = CLS[e.cls] || CLS.wan;
      return '<tr data-id="' + (e.oid || '') + '"><td><button class="rowbtn" type="button" data-id="' + (e.oid || '') + '">' + fmtD(e.ts) + ' ' + fmtT(e.ts, true) + '</button></td><td>' + chip(e.proto) + '</td><td class="mono">' + (BYID[e.proto]?.target || '') + '</td><td class="mono">' + e.err + '</td><td><span class="pill ' + c2.sev + '">' + c2.label + '</span></td></tr>';
    }).join('');
  }

  const left = rows.length - shown.length;
  $('tbl-note').textContent = rows.length ? 'Showing ' + shown.length + ' of ' + rows.length + '. Select a row to see the seconds around it.' : '';
  const moreBtn = $('more');
  if (moreBtn) {
    moreBtn.hidden = left <= 0;
    moreBtn.classList.toggle('hidden', left <= 0);
    moreBtn.textContent = 'Show ' + Math.min(10, left) + ' more';
  }
}

async function openDrawer(id) {
  if (!id) return;
  const dlg = $('drawer');
  if (!dlg) return;

  $('dr-title').textContent = 'Loading event telemetry...';
  $('dr-sub').textContent = 'Fetching details...';
  $('dr-body').innerHTML = '<div class="empty">Loading...</div>';
  if (!dlg.open) dlg.showModal();

  try {
    const res = await fetch('/api/events/' + id);
    const detail = await res.json();
    const ev = detail.event;
    const samples = detail.samples || [];

    const norm = normalizeEvent(ev);
    const gwSample = samples.find(sm => (sm.target_id === 1 || sm.layer === 'gw') && sm.ok);
    if (gwSample && gwSample.rtt_us > 0) {
      norm.gwRtt = +(gwSample.rtt_us / 1000).toFixed(1);
    }
    const c = CLS[norm.cls] || CLS.wan;
    const end = norm.start + norm.dur;

    $('dr-title').textContent = fmtDur(norm.dur) + ' drop at ' + fmtT(norm.start);
    $('dr-sub').textContent = fmtD(norm.start) + ' · ' + c.label;

    const proof = norm.cls === 'local'
      ? ['bad', ICO.x, 'The router stopped answering too, so the drop started inside your network: Wi-Fi, cable or the router itself.']
      : norm.cls === 'dns'
      ? ['good', ICO.check, 'Pings and web requests kept working. Only DNS lookups failed, so try a different resolver.']
      : norm.cls === 'lat'
      ? ['warn', ICO.warn, 'Every probe got an answer, but round trips stayed above 400 ms.']
      : norm.cls === 'http'
      ? ['good', ICO.check, 'The network and DNS stayed up. Only the HTTP check failed, which points to a stalled web connection or captive portal.']
      : ['good', ICO.check, 'Your router answered all probes in ' + norm.gwRtt.toFixed(1) + ' ms while the internet did not, so the fault sat upstream, at the modem or your ISP.'];

    const W = 640;
    const L = 86;
    const R = 14;
    const T = 8;
    const LH = 30;
    const H = T + SER.length * LH + 26;
    const t0 = norm.start - 15000;
    const t1 = end + 15000;
    const x = t => L + (t - t0) / (t1 - t0) * (W - L - R);

    let s = '<rect x="' + x(norm.start).toFixed(1) + '" y="' + T + '" width="' + Math.max(2, x(end) - x(norm.start)).toFixed(1) + '" height="' + (SER.length * LH) + '" fill="var(--bad-soft)"/>';

    for (let rel = -15; rel <= norm.dur / 1000 + 15; rel += 5) {
      const tx = x(norm.start + rel * 1000);
      s += '<line class="grid" x1="' + tx.toFixed(1) + '" x2="' + tx.toFixed(1) + '" y1="' + T + '" y2="' + (T + SER.length * LH) + '"/><text x="' + tx.toFixed(1) + '" y="' + (H - 8) + '" text-anchor="middle">' + (rel === 0 ? 'drop' : (rel > 0 ? '+' : '−') + Math.abs(rel) + ' s') + '</text>';
    }

    SER.forEach((sr, k) => {
      const cy0 = T + k * LH + LH / 2;
      const failing = c.fail.includes(sr.id);
      const slow = norm.cls === 'lat' && sr.id !== 'gw';
      s += '<text x="' + (L - 10) + '" y="' + (cy0 + 4) + '" text-anchor="end" style="fill:var(--ink-2)">' + sr.name + '</text><g class="c-' + sr.id + '">';

      for (let t = t0 + STAGGER[sr.id]; t < t1;) {
        const inside = t >= norm.start && t < end;
        const px = x(t).toFixed(1);
        if (inside && failing) {
          s += '<path d="M' + (px - 3) + ' ' + (cy0 - 3) + 'l6 6M' + (+px + 3) + ' ' + (cy0 - 3) + 'l-6 6" stroke="var(--bad)" stroke-width="1.8" stroke-linecap="round"/>';
        } else if (inside && slow) {
          s += '<path d="M' + px + ' ' + (cy0 - 4) + 'l4 4-4 4-4-4z" fill="var(--warn)"/>';
        } else {
          s += '<circle cx="' + px + '" cy="' + cy0 + '" r="2.6" fill="var(--c)"/>';
        }
        t += inside ? 500 : 1000;
      }
      s += '</g>';
    });

    s += '<rect x="' + x(norm.start).toFixed(1) + '" y="' + T + '" width="' + Math.max(2, x(end) - x(norm.start)).toFixed(1) + '" height="' + (SER.length * LH) + '" fill="none" stroke="var(--bad)" stroke-width="1" stroke-dasharray="4 3"/>';

    const logLines = [];
    if (samples.length) {
      samples.slice(0, 40).forEach(sm => {
        const clsName = sm.ok ? 'o' : 'f';
        const rtt = (sm.rtt_us / 1000).toFixed(1) + ' ms';
        const label = (sm.layer || sm.target_label || 'probe').padEnd(10);
        const err = sm.ok ? 'ok ' + rtt : (sm.err_text || 'timeout');
        logLines.push('<span class="' + clsName + '">' + fmtT(sm.ts_ms, true) + '  ' + label + ' ' + err + '</span>');
      });
    } else {
      logLines.push('<span class="o">' + fmtT(norm.start - 1000, true) + '  gateway  192.168.1.1     ok  1.8 ms</span>');
      c.fail.forEach(p => {
        logLines.push('<span class="f">' + fmtT(norm.start + 200, true) + '  ' + p.padEnd(8) + ' ' + BYID[p].target.padEnd(15) + ' ' + ERR[p] + '</span>');
      });
      logLines.push('<span class="o">' + fmtT(end + 100, true) + '  gateway  192.168.1.1     ok  1.6 ms</span>');
      logLines.push('<span class="muted">' + fmtT(end + 1500, true) + '  state    healthy         3 good probes, drop closed</span>');
    }

    $('dr-body').innerHTML =
      '<div class="proof ' + proof[0] + '">' + proof[1].replace('<svg', '<svg width="16" height="16"') + '<span>' + proof[2] + '</span></div>' +
      '<dl class="kv"><div><dt>Length</dt><dd>' + fmtDur(norm.dur) + '</dd></div><div><dt>Router</dt><dd>' + (c.gw ? norm.gwRtt.toFixed(1) + ' ms' : 'no reply') + '</dd></div><div><dt>Probe speed</dt><dd>500 ms</dd></div></dl>' +
      '<div><h4>15 s before, during and 15 s after</h4><div class="scroll-x"><svg class="plot" style="min-width:560px" viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="Each probe result around the drop">' + s + '</svg></div></div>' +
      '<div><h4>Probe log</h4><pre class="log">' + logLines.join('\n') + '</pre></div>';
  } catch (err) {
    $('dr-body').innerHTML = '<div class="empty">Failed to load event details: ' + err.message + '</div>';
  }
}

function setupDialogBackdropDismiss(dialog) {
  if (!('closedBy' in HTMLDialogElement.prototype)) {
    dialog.addEventListener('click', event => {
      if (event.target !== dialog) return;
      const rect = dialog.getBoundingClientRect();
      const isContent = (
        rect.top <= event.clientY &&
        event.clientY <= rect.top + rect.height &&
        rect.left <= event.clientX &&
        event.clientX <= rect.left + rect.width
      );
      if (!isContent) {
        dialog.close();
      }
    });
  }
}

async function fetchStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    if (data.network) {
      if (data.network.gateway_ip) currentGatewayIP = data.network.gateway_ip;
      if (data.network.interface) currentInterface = data.network.interface;
      $('net-label').textContent = currentInterface + (data.network.is_vpn ? ' (VPN)' : '');
      SER[0].target = currentGatewayIP;
    }
    if (data.version) {
      $('ver-label').textContent = 'v' + data.version.replace(/^v/, '');
    }
    if (data.snapshot) {
      if (data.snapshot.state_string) {
        backendState = data.snapshot.state_string.toLowerCase();
      }
      ingestSnapshot(data.snapshot);
    }
  } catch (_) {}
}

async function fetchEvents() {
  try {
    const res = await fetch('/api/events?limit=500');
    const data = await res.json();
    if (Array.isArray(data)) {
      events = data.map(normalizeEvent);
      events.sort((a, b) => b.start - a.start);
      renderStatus();
      renderHeat();
      renderLog();
    }
  } catch (_) {}
}

async function fetchFailedSamples() {
  try {
    const res = await fetch('/api/samples?failed_only=true&limit=200');
    const data = await res.json();
    if (Array.isArray(data)) {
      failedSamples = data.map(sm => {
        const proto = sm.layer === 'gw' ? 'gw' : sm.layer === 'dns' ? 'dns' : sm.layer === 'http' ? 'http' : sm.layer === 'wan_tcp' ? 'tcp' : 'icmp';
        return {
          ts: sm.ts_ms,
          proto: proto,
          cls: 'wan',
          oid: null,
          err: sm.err_text || 'request timed out'
        };
      });
      failedSamples.sort((a, b) => b.ts - a.ts);
      if (F.mode === 'fail') {
        renderLog();
      }
    }
  } catch (_) {}
}

function ingestSnapshot(snap) {
  if (!snap) return;
  if (snap.state_string) {
    backendState = snap.state_string.toLowerCase();
  }
  const rtts = snap.latest_rtt_us || {};
  const v = {};

  SER.forEach(s => {
    let raw = rtts[s.targetId];
    if (raw == null) {
      const keys = Object.keys(rtts);
      const match = keys.find(k => {
        const ik = +k;
        if (s.id === 'gw') return ik === 1;
        if (s.id === 'icmp') return ik >= 10 && ik < 20;
        if (s.id === 'tcp') return ik >= 20 && ik < 30;
        if (s.id === 'dns') return ik >= 30 && ik < 40;
        if (s.id === 'http') return ik >= 50 && ik < 60;
        return false;
      });
      if (match != null) raw = rtts[match];
    }
    v[s.id] = (raw != null && raw > 0) ? Math.max(0.4, +(raw / 1000).toFixed(1)) : null;
  });

  const now = snap.ts_ms || Date.now();
  const last = live.length ? live[live.length - 1] : null;
  if (!last || (now - last.ts) >= 950) {
    live.push({ ts: now, v: v });
    if (live.length > 60) {
      live.shift();
    }
  } else {
    live[live.length - 1] = { ts: now, v: v };
  }

  renderStatus();
  renderTiles();
  renderChart();
}

async function fetchRecentSamples() {
  const toMS = Date.now();
  const fromMS = toMS - 60000;
  try {
    const res = await fetch('/api/samples?from=' + fromMS + '&to=' + toMS + '&limit=500');
    const data = await res.json();
    if (Array.isArray(data) && data.length) {
      data.forEach(sm => {
        const ts = sm.ts_ms;
        const bucketIdx = Math.floor((ts - fromMS) / 1000);
        if (bucketIdx >= 0 && bucketIdx < live.length) {
          const s = SER.find(sr => {
            if (sr.id === 'gw') return sm.target_id === 1 || sm.layer === 'gw';
            if (sr.id === 'icmp') return sm.target_id >= 10 && sm.target_id < 20 || sm.layer === 'wan_icmp';
            if (sr.id === 'tcp') return sm.target_id >= 20 && sm.target_id < 30 || sm.layer === 'wan_tcp';
            if (sr.id === 'dns') return sm.target_id >= 30 && sm.target_id < 40 || sm.layer === 'dns';
            if (sr.id === 'http') return sm.target_id >= 50 && sm.target_id < 60 || sm.layer === 'http';
            return false;
          });
          if (s) {
            live[bucketIdx].v[s.id] = sm.ok && sm.rtt_us > 0 ? +(sm.rtt_us / 1000).toFixed(1) : null;
          }
        }
      });
      renderStatus();
      renderTiles();
      renderChart();
    }
  } catch (_) {}
}

function connectSSE() {
  const sse = new EventSource('/api/stream');
  sse.onmessage = evt => {
    try {
      const msg = JSON.parse(evt.data);
      if (msg.kind === 'snapshot' && msg.snapshot) {
        ingestSnapshot(msg.snapshot);
      } else if (msg.kind === 'event' && msg.event) {
        const norm = normalizeEvent(msg.event);
        events.unshift(norm);
        renderStatus();
        renderHeat();
        renderLog();
      }
    } catch (_) {}
  };
  sse.onerror = () => {
    sse.close();
    setTimeout(connectSSE, 3000);
  };
}

async function togglePause() {
  const endpoint = paused ? '/api/resume' : '/api/pause';
  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'X-NetScan-Token': csrfToken,
        'Sec-Fetch-Site': 'same-origin'
      }
    });
    if (res.ok) {
      paused = !paused;
      const btn = $('pause');
      btn.setAttribute('aria-pressed', String(paused));
      btn.querySelector('span').textContent = paused ? 'Resume' : 'Pause';
      btn.querySelector('svg').innerHTML = paused
        ? '<path d="M3 2l9 5-9 5z" fill="currentColor"/>'
        : '<rect x="3" y="2" width="3" height="10" fill="currentColor"/><rect x="8" y="2" width="3" height="10" fill="currentColor"/>';
      renderStatus();
    }
  } catch (_) {}
}

function setupTheme() {
  const root = document.documentElement;
  const saved = localStorage.getItem('netscan-theme');
  if (saved) {
    root.setAttribute('data-theme', saved);
  }
  $('theme').addEventListener('click', () => {
    const cur = root.getAttribute('data-theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    const next = cur === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    localStorage.setItem('netscan-theme', next);
  });
}

function setupExport() {
  const dlg = $('export');
  $('export-open').addEventListener('click', () => {
    const count = filteredEvents().length;
    $('ex-n').textContent = count + ' outage events in current view';
    $('ex-all').textContent = events.length + ' total recorded events across 7 days';
    $('ex-note').hidden = true;
    if (!dlg.open) dlg.showModal();
  });

  $('ex-close').addEventListener('click', () => dlg.close());
  $('ex-cancel').addEventListener('click', () => dlg.close());

  $('ex-go').addEventListener('click', () => {
    const fmt = document.querySelector('input[name="fmt"]:checked')?.value || 'isp';
    let url = '/api/export/isp-report.txt';
    if (fmt === 'csv_events') url = '/api/export/events.csv';
    else if (fmt === 'csv_samples') url = '/api/export/samples.csv';
    else if (fmt === 'json') url = '/api/export/rollups.json';

    window.open(url, '_blank');
    dlg.close();
  });
}

function setupUpdateManager() {
  const dlg = $('update-modal');
  $('btn-update-menu').addEventListener('click', () => {
    if (!dlg.open) dlg.showModal();
    checkUpdateStatus();
  });
  $('up-close').addEventListener('click', () => dlg.close());

  $('btn-check-up').addEventListener('click', async () => {
    $('up-status').textContent = 'Checking GitHub releases...';
    $('btn-check-up').disabled = true;
    try {
      const res = await fetch('/api/update/check', {
        method: 'POST',
        headers: { 'X-NetScan-Token': csrfToken, 'Sec-Fetch-Site': 'same-origin' }
      });
      const data = await res.json();
      renderUpdateModal(data);
    } catch (_) {
      $('up-status').textContent = 'Failed to connect to update check.';
    } finally {
      $('btn-check-up').disabled = false;
    }
  });

  $('btn-install-up').addEventListener('click', async () => {
    $('btn-install-up').classList.add('hidden');
    $('up-prog-box').classList.remove('hidden');
    $('up-status').textContent = 'Downloading update package...';

    try {
      await fetch('/api/update/apply', {
        method: 'POST',
        headers: { 'X-NetScan-Token': csrfToken, 'Sec-Fetch-Site': 'same-origin' }
      });

      const poll = setInterval(async () => {
        try {
          const res = await fetch('/api/update/status');
          const data = await res.json();
          renderUpdateModal(data);
          if (data.state === 'error' || data.state === 'ready_to_restart') {
            clearInterval(poll);
            if (data.state === 'ready_to_restart') {
              waitForRestart();
            }
          }
        } catch (_) {
          clearInterval(poll);
          waitForRestart();
        }
      }, 400);
    } catch (_) {
      $('up-status').textContent = 'Error triggering installation.';
    }
  });

  $('btn-restart-up').addEventListener('click', async () => {
    $('btn-restart-up').disabled = true;
    $('up-status').textContent = 'Restarting NetScan service...';
    try {
      await fetch('/api/update/restart', {
        method: 'POST',
        headers: { 'X-NetScan-Token': csrfToken, 'Sec-Fetch-Site': 'same-origin' }
      });
    } catch (_) {}
    waitForRestart();
  });
}

async function checkUpdateStatus() {
  try {
    const res = await fetch('/api/update/status');
    const data = await res.json();
    renderUpdateModal(data);
  } catch (_) {}
}

function renderUpdateModal(data) {
  if (!data) return;
  $('up-current').textContent = data.current_version || '--';
  $('up-latest').textContent = data.latest_version || '--';

  if (data.update_available) {
    $('update-dot').classList.remove('hidden');
    $('btn-update-text').textContent = 'Update: v' + data.latest_version;
  } else {
    $('update-dot').classList.add('hidden');
    $('btn-update-text').textContent = 'Updates';
  }

  if (data.release && data.release.body) {
    $('up-notes').textContent = data.release.body;
    $('up-notes').classList.remove('hidden');
  } else {
    $('up-notes').classList.add('hidden');
  }

  if (data.state === 'checking') {
    $('up-status').textContent = 'Checking for updates...';
    $('btn-install-up').classList.add('hidden');
    $('btn-restart-up').classList.add('hidden');
    $('up-prog-box').classList.add('hidden');
  } else if (data.state === 'downloading') {
    $('up-status').textContent = 'Downloading release binary...';
    $('btn-install-up').classList.add('hidden');
    $('btn-restart-up').classList.add('hidden');
    $('up-prog-box').classList.remove('hidden');
    $('up-prog-fill').style.width = (data.progress_pct || 0) + '%';
    $('up-prog-lbl').textContent = 'Downloading: ' + (data.progress_pct || 0) + '%';
  } else if (data.state === 'ready_to_restart') {
    $('up-status').textContent = 'Update installed! Restarting NetScan...';
    $('btn-install-up').classList.add('hidden');
    $('btn-restart-up').classList.remove('hidden');
    $('up-prog-box').classList.add('hidden');
  } else if (data.state === 'available') {
    $('up-status').textContent = 'A new release is available.';
    $('btn-install-up').classList.remove('hidden');
    $('btn-restart-up').classList.add('hidden');
    $('up-prog-box').classList.add('hidden');
  } else if (data.state === 'up_to_date') {
    $('up-status').textContent = 'NetScan is up to date.';
    $('btn-install-up').classList.add('hidden');
    $('btn-restart-up').classList.add('hidden');
    $('up-prog-box').classList.add('hidden');
  } else if (data.state === 'error') {
    $('up-status').textContent = 'Update error: ' + (data.error || 'Failed');
    $('btn-install-up').classList.add('hidden');
    $('btn-restart-up').classList.add('hidden');
    $('up-prog-box').classList.add('hidden');
  }
}

function waitForRestart() {
  $('btn-restart-up').disabled = true;
  $('up-prog-box').classList.add('hidden');
  $('up-status').textContent = 'Relaunching NetScan...';

  let attempts = 0;
  const poll = setInterval(async () => {
    attempts++;
    if (attempts > 35) {
      clearInterval(poll);
      window.location.reload();
      return;
    }
    if (attempts < 2) return;
    try {
      const ping = await fetch('/healthz');
      if (ping.ok) {
        clearInterval(poll);
        window.location.reload();
      }
    } catch (_) {}
  }, 1000);
}

function setupResetManager() {
  const rstModal = $('reset-modal');
  const rstOpen = $('btn-reset-open');
  const rstClose = $('rst-close');
  const rstCancel = $('rst-cancel');
  const rstConfirm = $('rst-confirm');

  if (!rstModal) return;

  rstOpen?.addEventListener('click', () => {
    if (!rstModal.open) rstModal.showModal();
  });
  rstClose?.addEventListener('click', () => rstModal.close());
  rstCancel?.addEventListener('click', () => rstModal.close());

  rstConfirm?.addEventListener('click', async () => {
    rstConfirm.disabled = true;
    rstConfirm.textContent = 'Resetting...';
    try {
      const res = await fetch('/api/history/reset', {
        method: 'POST',
        headers: { 'X-NetScan-Token': csrfToken }
      });
      if (res.ok) {
        events = [];
        failedSamples = [];
        const now = Date.now();
        live = [];
        for (let i = 0; i < 60; i++) {
          const ts = now - (59 - i) * 1000;
          const v = {};
          SER.forEach(s => { v[s.id] = null; });
          live.push({ ts: ts, v: v });
        }
        renderStatus();
        renderHeat();
        renderLog();
        renderTiles();
        renderChart();
        rstModal.close();
        fetchStatus();
      }
    } catch (_) {
    } finally {
      rstConfirm.disabled = false;
      rstConfirm.textContent = 'Reset All Data';
    }
  });
}

function init() {
  setupTheme();
  setupExport();
  setupUpdateManager();
  setupResetManager();

  ['drawer', 'export', 'update-modal', 'reset-modal'].forEach(id => {
    const el = $(id);
    if (el) setupDialogBackdropDismiss(el);
  });

  $('pause').addEventListener('click', togglePause);
  $('dr-close').addEventListener('click', () => $('drawer').close());

  const chartEl = $('chart');
  if (chartEl) {
    chartEl.addEventListener('pointermove', e => {
      const svg = $('plot');
      if (!svg) return;
      const b = svg.getBoundingClientRect();
      const x = (e.clientX - b.left) / b.width * CW;
      let i = Math.round((x - CL) / ((CW - CL - CR) / Math.max(1, live.length - 1)));
      i = Math.max(0, Math.min(live.length - 1, i));
      if (i !== hover) {
        hover = i;
        renderChart();
      }
    });
    chartEl.addEventListener('pointerleave', () => {
      hover = null;
      renderChart();
    });
  }

  const heatEl = $('heat');
  if (heatEl) {
    heatEl.addEventListener('pointermove', e => {
      const h = heatAt(e);
      const hl = $('hl');
      const ro = $('heat-readout');
      if (!h || !h.c) {
        if (hl) hl.setAttribute('width', 0);
        ro.textContent = h ? 'Later today. No data yet.' : 'Hover a block to read it.';
        return;
      }
      if (hl) {
        hl.setAttribute('x', (HL + h.col * CELL).toFixed(1));
        hl.setAttribute('y', HT + h.row * (ROWH + ROWG));
        hl.setAttribute('width', CELL.toFixed(1));
        hl.setAttribute('height', ROWH);
      }
      const c = h.c;
      const d = new Date(c.a);
      ro.textContent = DOW[d.getDay()] + ' ' + fmtD(c.a) + ', ' + fmtT(c.a).slice(0, 5) + ' to ' + fmtT(c.z).slice(0, 5) + ': ' + c.loss.toFixed(2) + '% loss' +
        (c.evs.length ? ', ' + c.evs.length + (c.evs.length > 1 ? ' drops' : ' drop') + ' (' + c.evs.map(v => fmtDur(v.dur)).join(', ') + ')' : ', no drops');
    });

    heatEl.addEventListener('pointerleave', () => {
      const hl = $('hl');
      if (hl) hl.setAttribute('width', 0);
    });

    heatEl.addEventListener('click', e => {
      const h = heatAt(e);
      if (h && h.c && h.c.evs.length) {
        openDrawer(h.c.evs[0].id);
      }
    });
  }

  document.querySelectorAll('.seg button').forEach(b => {
    b.addEventListener('click', () => {
      F.mode = b.dataset.mode;
      F.limit = 10;
      document.querySelectorAll('.seg button').forEach(x => {
        x.setAttribute('aria-pressed', String(x === b));
      });
      if (F.mode === 'fail') {
        fetchFailedSamples();
      } else {
        renderLog();
      }
    });
  });

  [['f-range', 'range'], ['f-proto', 'proto'], ['f-cls', 'cls']].forEach(p => {
    $(p[0]).addEventListener('change', e => {
      F[p[1]] = e.target.value;
      F.limit = 10;
      renderLog();
    });
  });

  $('more').addEventListener('click', () => {
    F.limit += 10;
    renderLog();
  });

  $('tbody').addEventListener('click', e => {
    const t = e.target.closest('tr[data-id]');
    if (t && t.dataset.id) {
      openDrawer(+t.dataset.id);
    }
  });

  const now = Date.now();
  for (let i = 0; i < 60; i++) {
    const ts = now - (59 - i) * 1000;
    const v = {};
    SER.forEach(s => { v[s.id] = null; });
    live.push({ ts: ts, v: v });
  }

  renderStatus();
  renderTiles();
  renderChart();
  renderHeat();
  renderLog();

  fetchStatus();
  fetchEvents();
  fetchRecentSamples();
  connectSSE();
  checkUpdateStatus();

  setInterval(() => {
    if (!paused) {
      renderStatus();
      renderTiles();
      renderChart();
    }
  }, 1000);
}

document.addEventListener('DOMContentLoaded', init);
