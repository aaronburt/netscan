const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';

const state = {
  liveSamples: [],
  maxLiveSeconds: 60,
  timelineRollups: [],
  timelineRangeHours: 24,
  events: [],
  isPaused: false,
};

const dom = {
  globalDot: document.getElementById('global-dot'),
  globalPill: document.getElementById('global-pill'),
  netLabel: document.getElementById('net-label'),
  gwLabel: document.getElementById('gw-label'),
  valGW: document.getElementById('val-gw'),
  valWANICMP: document.getElementById('val-wan-icmp'),
  valWANTCP: document.getElementById('val-wan-tcp'),
  valDNS: document.getElementById('val-dns'),
  valHTTP: document.getElementById('val-http'),
  btnPause: document.getElementById('btn-pause'),
  btnExportMenu: document.getElementById('btn-export-menu'),
  liveCanvas: document.getElementById('live-canvas'),
  timelineCanvas: document.getElementById('timeline-canvas'),
  eventsTbody: document.getElementById('events-tbody'),
  eventCountBadge: document.getElementById('event-count-badge'),
  filterKind: document.getElementById('filter-kind'),
  filterClass: document.getElementById('filter-class'),
  drilldownModal: document.getElementById('drilldown-modal'),
  drilldownTitle: document.getElementById('drilldown-title'),
  drilldownSummary: document.getElementById('drilldown-summary'),
  drilldownTbody: document.getElementById('drilldown-tbody'),
  modalBackdrop: document.getElementById('modal-backdrop'),
  btnCloseModal: document.getElementById('btn-close-modal'),
  exportModal: document.getElementById('export-modal'),
  exportBackdrop: document.getElementById('export-backdrop'),
  btnCloseExport: document.getElementById('btn-close-export'),
  btnUpdateMenu: document.getElementById('btn-update-menu'),
  updateDot: document.getElementById('update-dot'),
  btnUpdateText: document.getElementById('btn-update-text'),
  updateModal: document.getElementById('update-modal'),
  updateBackdrop: document.getElementById('update-backdrop'),
  btnCloseUpdate: document.getElementById('btn-close-update'),
  updateCurrentVersion: document.getElementById('update-current-version'),
  updateLatestVersion: document.getElementById('update-latest-version'),
  updateStatusMsg: document.getElementById('update-status-msg'),
  updateNotesSection: document.getElementById('update-release-notes-section'),
  updateNotesBody: document.getElementById('update-notes-body'),
  updateProgressContainer: document.getElementById('update-progress-container'),
  updateProgressFill: document.getElementById('update-progress-fill'),
  updateProgressLabel: document.getElementById('update-progress-label'),
  btnCheckUpdates: document.getElementById('btn-check-updates'),
  btnInstallUpdate: document.getElementById('btn-install-update'),
  btnRestartApp: document.getElementById('btn-restart-app'),
};

function init() {
  setupEventListeners();
  setupCanvas(dom.liveCanvas);
  setupCanvas(dom.timelineCanvas);
  connectSSE();
  fetchInitialData();
  fetchEvents();
  fetchTimelineRollups();
  checkUpdateStatus();

  window.addEventListener('resize', () => {
    setupCanvas(dom.liveCanvas);
    setupCanvas(dom.timelineCanvas);
    drawLiveChart();
    drawTimelineChart();
  });
}

function setupEventListeners() {
  dom.btnPause.addEventListener('click', togglePause);
  dom.btnExportMenu.addEventListener('click', () => dom.exportModal.classList.remove('hidden'));
  dom.btnCloseExport.addEventListener('click', () => dom.exportModal.classList.add('hidden'));
  dom.exportBackdrop.addEventListener('click', () => dom.exportModal.classList.add('hidden'));

  dom.btnUpdateMenu.addEventListener('click', () => {
    dom.updateModal.classList.remove('hidden');
    checkUpdateStatus();
  });
  dom.btnCloseUpdate.addEventListener('click', () => dom.updateModal.classList.add('hidden'));
  dom.updateBackdrop.addEventListener('click', () => dom.updateModal.classList.add('hidden'));

  dom.btnCheckUpdates.addEventListener('click', triggerUpdateCheck);
  dom.btnInstallUpdate.addEventListener('click', triggerUpdateInstall);
  dom.btnRestartApp.addEventListener('click', triggerUpdateRestart);

  if (window.location.hash === '#update') {
    dom.updateModal.classList.remove('hidden');
    checkUpdateStatus();
  }

  dom.btnCloseModal.addEventListener('click', () => dom.drilldownModal.classList.add('hidden'));
  dom.modalBackdrop.addEventListener('click', () => dom.drilldownModal.classList.add('hidden'));

  dom.filterKind.addEventListener('change', fetchEvents);
  dom.filterClass.addEventListener('change', fetchEvents);

  document.querySelectorAll('.time-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      document.querySelectorAll('.time-btn').forEach(b => b.classList.remove('active'));
      e.target.classList.add('active');
      state.timelineRangeHours = parseInt(e.target.dataset.hours, 10);
      fetchTimelineRollups();
    });
  });
}

function setupCanvas(canvas) {
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = Math.floor(rect.width * dpr);
  canvas.height = Math.floor(rect.height * dpr);
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
}

function connectSSE() {
  const es = new EventSource('/api/stream');

  es.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data);
      if (msg.kind === 'snapshot' && msg.snapshot) {
        updateSnapshot(msg.snapshot);
      }
      if (msg.kind === 'event' && msg.event) {
        fetchEvents();
      }
    } catch (_) {}
  };

  es.onerror = () => {
    setTimeout(connectSSE, 3000);
  };
}

async function fetchInitialData() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    if (data.network) {
      dom.netLabel.textContent = data.network.ssid ? `Wi-Fi (${data.network.ssid})` : (data.network.is_vpn ? 'VPN Active' : (data.network.interface || 'Ethernet / LAN'));
      dom.gwLabel.textContent = `Gateway: ${data.network.gateway_ip || 'N/A'}`;
    }
  } catch (_) {}
}

function updateSnapshot(snap) {
  dom.globalDot.className = `status-indicator ${snap.state_string.toLowerCase()}`;
  dom.globalPill.className = `status-pill ${snap.state_string.toLowerCase()}`;
  dom.globalPill.textContent = snap.state_string;

  const rtt = snap.latest_rtt_us || {};
  dom.valGW.textContent = rtt['1'] ? `${(rtt['1'] / 1000).toFixed(1)} ms` : '-- ms';
  dom.valWANICMP.textContent = rtt['10'] ? `${(rtt['10'] / 1000).toFixed(1)} ms` : '-- ms';
  dom.valWANTCP.textContent = rtt['20'] ? `${(rtt['20'] / 1000).toFixed(1)} ms` : '-- ms';
  dom.valDNS.textContent = rtt['30'] ? `${(rtt['30'] / 1000).toFixed(1)} ms` : '-- ms';
  dom.valHTTP.textContent = rtt['50'] ? `${(rtt['50'] / 1000).toFixed(1)} ms` : '-- ms';

  state.liveSamples.push({
    ts: snap.ts_ms,
    state: snap.state_string,
    gw: rtt['1'] ? rtt['1'] / 1000 : null,
    wan: rtt['10'] ? rtt['10'] / 1000 : null,
    tcp: rtt['20'] ? rtt['20'] / 1000 : null,
    dns: rtt['30'] ? rtt['30'] / 1000 : null,
  });

  const cutoff = snap.ts_ms - (state.maxLiveSeconds * 1000);
  state.liveSamples = state.liveSamples.filter(s => s.ts >= cutoff);

  drawLiveChart();
}

function drawLiveChart() {
  const canvas = dom.liveCanvas;
  const ctx = canvas.getContext('2d');
  const rect = canvas.getBoundingClientRect();
  const w = rect.width;
  const h = rect.height;

  ctx.clearRect(0, 0, w, h);

  const paddingLeft = 12;
  const paddingRight = 48;
  const paddingTop = 12;
  const paddingBottom = 22;
  const plotWidth = w - paddingLeft - paddingRight;
  const plotHeight = h - paddingTop - paddingBottom;

  ctx.lineWidth = 1;
  ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
  ctx.fillStyle = '#64748b';
  ctx.font = '10px "SF Mono", Menlo, Consolas, monospace';
  ctx.textAlign = 'right';

  const maxRTT = 100;
  const ySteps = [0, 25, 50, 75, 100];
  for (const step of ySteps) {
    const y = paddingTop + plotHeight - (step / maxRTT) * plotHeight;
    ctx.beginPath();
    ctx.setLineDash([4, 4]);
    ctx.moveTo(paddingLeft, y);
    ctx.lineTo(w - paddingRight, y);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillText(`${step}ms`, w - 10, y + 3);
  }

  const timeTicks = [
    { label: '-60s', frac: 0.0 },
    { label: '-45s', frac: 0.25 },
    { label: '-30s', frac: 0.5 },
    { label: '-15s', frac: 0.75 },
    { label: 'Now', frac: 1.0 },
  ];
  ctx.textAlign = 'center';
  for (const t of timeTicks) {
    const x = paddingLeft + t.frac * plotWidth;
    ctx.fillText(t.label, x, h - 6);
  }

  if (state.liveSamples.length < 2) {
    ctx.fillStyle = '#64748b';
    ctx.font = '12px system-ui, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Awaiting real-time probe telemetry...', w / 2, h / 2);
    return;
  }

  const now = state.liveSamples[state.liveSamples.length - 1].ts;
  const startTime = now - (state.maxLiveSeconds * 1000);

  function plotLine(key, color) {
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.lineJoin = 'round';
    ctx.lineCap = 'round';
    ctx.beginPath();
    let started = false;

    for (const s of state.liveSamples) {
      const val = s[key];
      if (val === null || val === undefined) {
        started = false;
        continue;
      }
      const x = paddingLeft + ((s.ts - startTime) / (state.maxLiveSeconds * 1000)) * plotWidth;
      const y = paddingTop + plotHeight - (Math.min(val, maxRTT) / maxRTT) * plotHeight;

      if (!started) {
        ctx.moveTo(x, y);
        started = true;
      } else {
        ctx.lineTo(x, y);
      }
    }
    ctx.stroke();
  }

  plotLine('gw', '#10b981');
  plotLine('wan', '#38bdf8');
  plotLine('tcp', '#f59e0b');
  plotLine('dns', '#a855f7');
}

async function fetchTimelineRollups() {
  const now = Date.now();
  const fromMS = now - (state.timelineRangeHours * 3600 * 1000);
  try {
    const res = await fetch(`/api/rollups?from=${fromMS}&to=${now}`);
    const data = await res.json();
    state.timelineRollups = data || [];
    drawTimelineChart();
  } catch (_) {}
}

function drawTimelineChart() {
  const canvas = dom.timelineCanvas;
  const ctx = canvas.getContext('2d');
  const rect = canvas.getBoundingClientRect();
  const w = rect.width;
  const h = rect.height;

  ctx.clearRect(0, 0, w, h);

  const paddingLeft = 12;
  const paddingRight = 48;
  const paddingTop = 12;
  const paddingBottom = 22;
  const plotWidth = w - paddingLeft - paddingRight;
  const plotHeight = h - paddingTop - paddingBottom;

  ctx.lineWidth = 1;
  ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
  ctx.fillStyle = '#64748b';
  ctx.font = '10px "SF Mono", Menlo, Consolas, monospace';
  ctx.textAlign = 'right';

  const maxRTT = 100;
  const ySteps = [0, 50, 100];
  for (const step of ySteps) {
    const y = paddingTop + plotHeight - (step / maxRTT) * plotHeight;
    ctx.beginPath();
    ctx.setLineDash([4, 4]);
    ctx.moveTo(paddingLeft, y);
    ctx.lineTo(w - paddingRight, y);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillText(`${step}ms`, w - 10, y + 3);
  }

  const rangeHours = state.timelineRangeHours;
  let ticks = [];
  if (rangeHours === 1) {
    ticks = ['-60m', '-45m', '-30m', '-15m', 'Now'];
  } else if (rangeHours === 6) {
    ticks = ['-6h', '-4.5h', '-3h', '-1.5h', 'Now'];
  } else if (rangeHours === 24) {
    ticks = ['-24h', '-18h', '-12h', '-6h', 'Now'];
  } else {
    ticks = ['-7d', '-5d', '-3d', '-1d', 'Now'];
  }

  ctx.textAlign = 'center';
  for (let i = 0; i < ticks.length; i++) {
    const x = paddingLeft + (i / (ticks.length - 1)) * plotWidth;
    ctx.fillText(ticks[i], x, h - 6);
  }

  if (state.timelineRollups.length === 0) {
    ctx.fillStyle = '#64748b';
    ctx.font = '12px system-ui, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Accumulating 1-minute historical rollups...', w / 2, h / 2);
    return;
  }

  const now = Date.now();
  const fromMS = now - (state.timelineRangeHours * 3600 * 1000);
  const span = now - fromMS;
  const barWidth = Math.max(2, (plotWidth / state.timelineRollups.length) - 1);

  for (const r of state.timelineRollups) {
    const x = paddingLeft + ((r.bucket_ms - fromMS) / span) * plotWidth;
    const loss = r.loss_pct || 0;
    const rtt = (r.p50_us || 0) / 1000;

    if (loss > 50) {
      ctx.fillStyle = '#ef4444';
      ctx.fillRect(x, paddingTop, barWidth, plotHeight);
    } else if (loss > 0) {
      ctx.fillStyle = '#f59e0b';
      ctx.fillRect(x, paddingTop, barWidth, plotHeight);
    } else {
      const barH = (Math.min(rtt, maxRTT) / maxRTT) * plotHeight;
      ctx.fillStyle = rtt > 50 ? '#f59e0b' : '#38bdf8';
      ctx.fillRect(x, paddingTop + plotHeight - barH, barWidth, Math.max(2, barH));
    }
  }
}

async function fetchEvents() {
  const kind = dom.filterKind.value;
  const classification = dom.filterClass.value;
  const params = new URLSearchParams();
  if (kind) params.set('kind', kind);
  if (classification) params.set('classification', classification);
  params.set('limit', '50');

  try {
    const res = await fetch(`/api/events?${params.toString()}`);
    const data = await res.json();
    state.events = data || [];
    renderEventsTable();
  } catch (_) {}
}

function renderEventsTable() {
  dom.eventCountBadge.textContent = `${state.events.length} events`;
  if (state.events.length === 0) {
    dom.eventsTbody.innerHTML = `<tr><td colspan="7" class="empty-state">No events recorded matching criteria.</td></tr>`;
    return;
  }

  dom.eventsTbody.innerHTML = state.events.map(e => {
    const start = new Date(e.start_ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const dur = e.duration_ms !== null && e.duration_ms !== undefined ? `${(e.duration_ms / 1000).toFixed(1)}s` : 'Active';
    const tagClass = e.kind === 'outage' ? 'tag-outage' : (e.kind === 'blip' ? 'tag-blip' : 'tag-latency');
    const gwHealth = `${(e.gateway_ok_pct || 100).toFixed(1)}%`;
    const uncert = `±${((e.start_uncert_ms || 1000) / 1000).toFixed(1)}s`;

    return `
      <tr>
        <td><strong>${start}</strong></td>
        <td><span class="tag ${tagClass}">${e.kind}</span></td>
        <td><code>${e.classification}</code></td>
        <td>${dur}</td>
        <td>${gwHealth}</td>
        <td>${uncert}</td>
        <td><button class="btn btn-secondary btn-sm" onclick="window.inspectEvent(${e.id})">Inspect</button></td>
      </tr>
    `;
  }).join('');
}

window.inspectEvent = async function(id) {
  try {
    const res = await fetch(`/api/events/${id}`);
    const detail = await res.json();
    if (!detail || !detail.event) return;

    dom.drilldownTitle.textContent = `Event #${detail.event.id} — ${detail.event.classification} (${detail.event.kind.toUpperCase()})`;
    const durStr = detail.event.duration_ms ? `${(detail.event.duration_ms / 1000).toFixed(2)}s` : 'Ongoing';
    const gwStr = `${(detail.event.gateway_ok_pct || 100).toFixed(1)}%`;

    dom.drilldownSummary.innerHTML = `
      <div class="drilldown-stat-box">
        <span class="drilldown-stat-label">Start Timestamp</span>
        <span class="drilldown-stat-val">${new Date(detail.event.start_ms).toLocaleTimeString()} (±${((detail.event.start_uncert_ms || 1000) / 1000).toFixed(1)}s)</span>
      </div>
      <div class="drilldown-stat-box">
        <span class="drilldown-stat-label">Duration</span>
        <span class="drilldown-stat-val">${durStr}</span>
      </div>
      <div class="drilldown-stat-box">
        <span class="drilldown-stat-label">Gateway Reachability</span>
        <span class="drilldown-stat-val">${gwStr}</span>
      </div>
      <div class="drilldown-stat-box">
        <span class="drilldown-stat-label">Fault Layer</span>
        <span class="drilldown-stat-val"><code>${detail.event.classification}</code></span>
      </div>
    `;

    dom.drilldownTbody.innerHTML = (detail.samples || []).map(s => {
      const time = new Date(s.ts_ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 });
      const statusBadge = s.ok ? '<span style="color:#10b981;font-weight:600">OK</span>' : '<span style="color:#ef4444;font-weight:600">FAIL</span>';
      const rtt = s.rtt_us ? `${(s.rtt_us / 1000).toFixed(1)} ms` : '--';
      const phases = s.dns_us ? `DNS: ${(s.dns_us/1000).toFixed(0)}ms | TCP: ${(s.tcp_us/1000).toFixed(0)}ms | TTFB: ${(s.ttfb_us/1000).toFixed(0)}ms` : '--';
      const err = s.err_text || (s.err ? `Code ${s.err}` : '');

      return `
        <tr>
          <td>${time}</td>
          <td>${s.target_label || s.target_id}</td>
          <td><code>${s.layer || ''}</code></td>
          <td>${statusBadge}</td>
          <td>${rtt}</td>
          <td><small>${phases}</small></td>
          <td style="color:#f87171">${err}</td>
        </tr>
      `;
    }).join('');

    dom.drilldownModal.classList.remove('hidden');
  } catch (_) {}
};

async function togglePause() {
  const endpoint = state.isPaused ? '/api/resume' : '/api/pause';
  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'X-NetScan-Token': csrfToken,
        'Sec-Fetch-Site': 'same-origin',
      },
    });
    if (res.ok) {
      state.isPaused = !state.isPaused;
      dom.btnPause.textContent = state.isPaused ? 'Resume' : 'Pause';
    }
  } catch (_) {}
}

async function checkUpdateStatus() {
  try {
    const res = await fetch('/api/update/status');
    const data = await res.json();
    renderUpdateUI(data);
  } catch (_) {}
}

function renderUpdateUI(data) {
  if (!data) return;

  dom.updateCurrentVersion.textContent = data.current_version || '--';
  dom.updateLatestVersion.textContent = data.latest_version || '--';

  if (data.update_available) {
    dom.updateDot.classList.remove('hidden');
    dom.btnUpdateText.textContent = `Update: v${data.latest_version}`;
  } else {
    dom.updateDot.classList.add('hidden');
    dom.btnUpdateText.textContent = 'Updates';
  }

  if (data.release && data.release.body) {
    dom.updateNotesBody.textContent = data.release.body;
    dom.updateNotesSection.classList.remove('hidden');
  } else {
    dom.updateNotesSection.classList.add('hidden');
  }

  dom.btnCheckUpdates.disabled = false;
  dom.btnCheckUpdates.textContent = 'Check Now';

  if (data.state === 'checking') {
    dom.updateStatusMsg.textContent = 'Checking for updates...';
    dom.btnCheckUpdates.disabled = true;
    dom.btnCheckUpdates.textContent = 'Checking...';
    dom.btnInstallUpdate.classList.add('hidden');
    dom.btnRestartApp.classList.add('hidden');
    dom.updateProgressContainer.classList.add('hidden');
  } else if (data.state === 'downloading') {
    dom.updateStatusMsg.textContent = 'Downloading and preparing update...';
    dom.btnInstallUpdate.classList.add('hidden');
    dom.btnRestartApp.classList.add('hidden');
    dom.updateProgressContainer.classList.remove('hidden');
    dom.updateProgressFill.style.width = `${data.progress_pct || 0}%`;
    dom.updateProgressLabel.textContent = `Downloading: ${data.progress_pct || 0}%`;
  } else if (data.state === 'ready_to_restart') {
    dom.updateStatusMsg.textContent = 'Update installed! Relaunching NetScan...';
    dom.btnInstallUpdate.classList.add('hidden');
    dom.btnRestartApp.classList.remove('hidden');
    dom.updateProgressContainer.classList.add('hidden');
  } else if (data.state === 'available') {
    dom.updateStatusMsg.textContent = 'A new release is available.';
    dom.btnInstallUpdate.classList.remove('hidden');
    dom.btnRestartApp.classList.add('hidden');
    dom.updateProgressContainer.classList.add('hidden');
  } else if (data.state === 'up_to_date') {
    dom.updateStatusMsg.textContent = 'NetScan is up to date.';
    dom.btnInstallUpdate.classList.add('hidden');
    dom.btnRestartApp.classList.add('hidden');
    dom.updateProgressContainer.classList.add('hidden');
  } else if (data.state === 'error') {
    dom.updateStatusMsg.textContent = `Update check failed: ${data.error || 'Unknown error'}`;
    dom.btnInstallUpdate.classList.add('hidden');
    dom.btnRestartApp.classList.add('hidden');
    dom.updateProgressContainer.classList.add('hidden');
  }
}

async function triggerUpdateCheck() {
  dom.updateStatusMsg.textContent = 'Checking for updates...';
  dom.btnCheckUpdates.disabled = true;
  dom.btnCheckUpdates.textContent = 'Checking...';

  try {
    const res = await fetch('/api/update/check', {
      method: 'POST',
      headers: {
        'X-NetScan-Token': csrfToken,
        'Sec-Fetch-Site': 'same-origin',
      },
    });
    const data = await res.json();
    renderUpdateUI(data);
  } catch (err) {
    dom.updateStatusMsg.textContent = 'Error connecting to server';
    dom.btnCheckUpdates.disabled = false;
    dom.btnCheckUpdates.textContent = 'Check Now';
  }
}

function waitForServerRestart() {
  dom.btnRestartApp.disabled = true;
  dom.updateProgressContainer.classList.add('hidden');
  dom.updateStatusMsg.textContent = 'Relaunching NetScan...';

  let attempts = 0;
  const checkInterval = setInterval(async () => {
    attempts++;
    if (attempts > 30) {
      clearInterval(checkInterval);
      window.location.reload();
      return;
    }
    if (attempts < 2) {
      return;
    }
    try {
      const ping = await fetch('/healthz');
      if (ping.ok) {
        clearInterval(checkInterval);
        window.location.reload();
      }
    } catch (_) {}
  }, 1000);
}

async function triggerUpdateInstall() {
  dom.btnInstallUpdate.classList.add('hidden');
  dom.updateProgressContainer.classList.remove('hidden');
  dom.updateProgressFill.style.width = '0%';
  dom.updateProgressLabel.textContent = 'Downloading: 0%';
  dom.updateStatusMsg.textContent = 'Downloading release...';

  try {
    await fetch('/api/update/apply', {
      method: 'POST',
      headers: {
        'X-NetScan-Token': csrfToken,
        'Sec-Fetch-Site': 'same-origin',
      },
    });

    const pollInterval = setInterval(async () => {
      try {
        const res = await fetch('/api/update/status');
        const data = await res.json();
        renderUpdateUI(data);
        if (data.state === 'error') {
          clearInterval(pollInterval);
        } else if (data.state === 'ready_to_restart') {
          clearInterval(pollInterval);
          waitForServerRestart();
        }
      } catch (_) {
        clearInterval(pollInterval);
        waitForServerRestart();
      }
    }, 400);
  } catch (err) {
    dom.updateStatusMsg.textContent = 'Failed to trigger installation';
  }
}

async function triggerUpdateRestart() {
  dom.btnRestartApp.disabled = true;
  dom.updateStatusMsg.textContent = 'Restarting NetScan...';

  try {
    await fetch('/api/update/restart', {
      method: 'POST',
      headers: {
        'X-NetScan-Token': csrfToken,
        'Sec-Fetch-Site': 'same-origin',
      },
    });
  } catch (_) {}

  waitForServerRestart();
}

document.addEventListener('DOMContentLoaded', init);
