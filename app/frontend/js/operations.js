/**
 * Cold-Storage Operations & Sensor Monitor - Client Application
 * Communicates exclusively with the FastAPI warehouse / data source endpoints.
 * Displays raw operational records and 9-sensor DHT22 telemetry without security evaluations.
 */

const API_BASE = '/api';
const POLL_INTERVAL_MS = 3000;
let isRequestInProgress = false;
let isMutatingState = false;
let isContinuousPlaying = false;
let continuousTimer = null;
let currentGeneration = 0;

// Sensor metadata mappings
const SENSOR_ROLES = {
  'SENSOR01': 'Ambient Room Central (Fixed)',
  'SENSOR02': 'Ambient Validation (Fixed)',
  'SENSOR03': 'Storage Corner (Fixed)',
  'SENSOR04': 'Wall-Mounted Monitor (Fixed)',
  'SENSOR05': 'Mobile Experimental Unit',
  'SENSOR06': 'Ambient Facility Monitor (Fixed)',
  'SENSOR07': 'Door Entry Perimeter (Fixed)',
  'SENSOR08': 'Cooling Unit Evaporator (Fixed)',
  'SENSOR09': 'Mobile Temperature Probe',
};

// DOM Elements
const el = {
  connectionBanner: document.getElementById('connection-banner'),
  backendHealth: document.getElementById('kpi-backend-health'),
  healthDot: document.getElementById('health-dot'),
  currentTime: document.getElementById('current-time'),

  // Source Notice & Progress
  sourceDescription: document.getElementById('source-description'),
  sourceBadge: document.getElementById('source-badge'),
  actionBadgeContainer: document.getElementById('action-badge-container'),
  playbackFill: document.getElementById('playback-fill'),

  // Section 1: Summary Cells
  opsWhId: document.getElementById('ops-wh-id'),
  opsWhStep: document.getElementById('ops-wh-step'),
  opsLastTimestamp: document.getElementById('ops-last-timestamp'),
  currentTemp: document.getElementById('ops-current-temp'),
  currentHum: document.getElementById('ops-current-hum'),
  currentDeltaT: document.getElementById('ops-current-delta-t'),
  currentActiveSensors: document.getElementById('ops-current-active-sensors'),
  currentAction: document.getElementById('ops-current-action'),
  currentInv: document.getElementById('ops-current-inv'),
  currentFreeCap: document.getElementById('ops-current-free-cap'),
  currentFlow: document.getElementById('ops-current-flow'),

  // Section 2: Sensor Matrix
  sensorMatrix: document.getElementById('sensor-matrix'),

  // Section 3: History Table
  historyTbody: document.getElementById('ops-history-tbody'),

  // Section 4: Controls
  btnStep: document.getElementById('btn-ops-step'),
  btnContinuous: document.getElementById('btn-ops-continuous'),
  txtContinuous: document.getElementById('txt-continuous'),
  seekInput: document.getElementById('ops-seek-step'),
  btnSeek: document.getElementById('btn-ops-seek'),
  btnReset: document.getElementById('btn-ops-reset'),
  btnToggleMode: document.getElementById('btn-ops-toggle-mode'),
  controlStatus: document.getElementById('ops-control-status'),
};

function formatTimestamp(isoString) {
  if (!isoString) return '--:--:--';
  try {
    const d = new Date(isoString);
    return d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
  } catch (e) {
    return isoString;
  }
}

function updateClock() {
  const now = new Date();
  if (el.currentTime) {
    el.currentTime.textContent = now.toTimeString().split(' ')[0] + ' UTC';
  }
}
setInterval(updateClock, 1000);
updateClock();

function setControlsDisabled(disabled) {
  if (el.btnStep) el.btnStep.disabled = disabled;
  if (el.btnReset) el.btnReset.disabled = disabled;
  if (el.btnSeek) el.btnSeek.disabled = disabled;
}

function handleConnectionFailure(err) {
  console.error('Failed to communicate with cold-storage backend:', err);
  if (el.connectionBanner) el.connectionBanner.classList.remove('hidden');
  if (el.backendHealth) el.backendHealth.textContent = 'OFFLINE (DISCONNECTED)';
  if (el.healthDot) el.healthDot.classList.add('offline');
  setControlsDisabled(true);
}

function restoreOnlineStatus() {
  if (el.connectionBanner) el.connectionBanner.classList.add('hidden');
  if (el.backendHealth) el.backendHealth.textContent = 'ONLINE';
  if (el.healthDot) el.healthDot.classList.remove('offline');
  if (!isMutatingState) {
    setControlsDisabled(false);
  }
}

// In-memory operator session token
let inMemoryOperatorToken = null;

async function fetchJson(url, options = {}) {
  const headers = { 'Accept': 'application/json', ...(options.headers || {}) };
  if (inMemoryOperatorToken && !headers['Authorization'] && !headers['X-Operator-Token']) {
    headers['Authorization'] = `Bearer ${inMemoryOperatorToken}`;
  }

  const res = await fetch(url, {
    credentials: 'same-origin',
    headers,
    ...options,
  });

  if (res.status === 401) {
    const promptMsg = 'Operator authentication required. Please enter your Operator Token:';
    const entered = window.prompt(promptMsg);
    if (entered && entered.trim()) {
      inMemoryOperatorToken = entered.trim();
      try {
        await fetch(`${API_BASE}/auth/login`, {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: inMemoryOperatorToken }),
        });
      } catch (loginErr) {
        console.warn('Session login error:', loginErr);
      }
      headers['Authorization'] = `Bearer ${inMemoryOperatorToken}`;
      return fetch(url, { credentials: 'same-origin', headers, ...options });
    }
  }

  if (!res.ok) {
    const errBody = await res.text();
    throw new Error(`HTTP ${res.status} ${res.statusText}: ${errBody}`);
  }
  return res.json();
}

function renderObservation(obs) {
  if (!obs) return;

  const isReal = obs.is_recorded_playback || obs.source === 'hohenheim';

  // Facility and Step
  if (el.opsWhId) el.opsWhId.textContent = obs.warehouse || 'W01';
  if (el.opsWhStep) el.opsWhStep.textContent = `Step ${obs.step}`;
  if (el.seekInput && !isContinuousPlaying) el.seekInput.value = obs.step;
  if (el.opsLastTimestamp) el.opsLastTimestamp.textContent = formatTimestamp(obs.timestamp);

  // Primary Telemetry
  if (el.currentTemp) el.currentTemp.textContent = obs.temperature != null ? obs.temperature.toFixed(1) : '--';
  if (el.currentHum) el.currentHum.textContent = obs.humidity != null ? obs.humidity.toFixed(1) : '--';

  // Quality & Delta T
  const q = obs.data_quality || {};
  if (el.currentDeltaT) {
    el.currentDeltaT.textContent = q.inter_sensor_temp_delta != null ? q.inter_sensor_temp_delta.toFixed(1) : '0.0';
  }
  if (el.currentActiveSensors) {
    const active = q.active_sensor_count != null ? q.active_sensor_count : 9;
    const total = q.total_sensors || 9;
    el.currentActiveSensors.textContent = `${active} / ${total}`;
  }

  // Active Action
  const action = obs.active_action || 'None (Normal Sealed)';
  if (el.opsCurrentAction) el.opsCurrentAction.textContent = action;
  if (el.actionBadgeContainer) {
    if (obs.active_action === 'Door opened') {
      el.actionBadgeContainer.innerHTML = `<span class="action-badge action-door-open">&bull; Door Opened Event</span>`;
    } else if (obs.active_action === 'Door closed') {
      el.actionBadgeContainer.innerHTML = `<span class="action-badge action-door-closed">&bull; Door Closed</span>`;
    } else if (obs.active_action) {
      el.actionBadgeContainer.innerHTML = `<span class="action-badge" style="background:#1e293b; color:#94a3b8; border:1px solid #334155;">&bull; ${obs.active_action}</span>`;
    } else {
      el.actionBadgeContainer.innerHTML = '';
    }
  }

  // Ledger cells
  if (el.currentInv) el.currentInv.textContent = obs.inventory != null ? `${obs.inventory.toFixed(1)}t` : 'N/A';
  if (el.currentFreeCap) el.currentFreeCap.textContent = obs.free_capacity != null ? `${obs.free_capacity.toFixed(1)}t` : 'N/A';
  if (el.currentFlow) {
    if (obs.inbound != null && obs.outbound != null) {
      el.currentFlow.textContent = `+${obs.inbound.toFixed(1)} / -${obs.outbound.toFixed(1)}t`;
    } else {
      el.currentFlow.textContent = 'N/A';
    }
  }

  // Notice Banner & Mode Badge
  if (el.sourceBadge) {
    el.sourceBadge.textContent = isReal ? 'RECORDED DATASET PLAYBACK' : 'SYNTHETIC SIMULATOR';
    el.sourceBadge.className = isReal ? 'badge badge-normal' : 'badge badge-low';
  }

  // 9-Sensor Matrix Grid
  renderSensorMatrix(obs.sensors, obs.active_action);
}

function renderSensorMatrix(sensors, activeAction) {
  if (!el.sensorMatrix) return;
  if (!sensors || Object.keys(sensors).length === 0) {
    el.sensorMatrix.innerHTML = `<div style="color: var(--text-muted); font-size: 0.85rem; padding: 0.5rem;">Multi-sensor spatial array not active in this data mode.</div>`;
    return;
  }

  let html = '';
  for (let i = 1; i <= 9; i++) {
    const sId = `SENSOR0${i}`;
    const sData = sensors[sId] || {};
    const t = sData.temperature;
    const h = sData.humidity;
    const isDropout = t == null || h == null;
    const role = SENSOR_ROLES[sId] || 'Storage Zone';

    html += `
      <div class="sensor-card ${isDropout ? 'dropout' : ''}">
        <div class="sensor-header">
          <span style="color: #fff;">${sId}</span>
          ${isDropout
            ? `<span class="badge" style="background: rgba(239,68,68,0.2); color: #f87171; border: 1px solid #ef4444; font-size: 0.65rem;">DROPOUT</span>`
            : `<span class="badge badge-normal" style="font-size: 0.65rem;">ONLINE</span>`}
        </div>
        <div style="font-size: 0.7rem; color: var(--text-muted);">${role}</div>
        <div class="sensor-readings" style="margin-top: 0.25rem;">
          <span style="color: var(--telemetry-sky);">${t != null ? t.toFixed(1) + '°C' : '<span style="color:#ef4444;">NaN</span>'}</span>
          <span style="color: var(--telemetry-indigo);">${h != null ? h.toFixed(1) + '%' : '<span style="color:#ef4444;">NaN</span>'}</span>
        </div>
      </div>
    `;
  }
  el.sensorMatrix.innerHTML = html;
}

function renderHistory(observations) {
  if (!el.historyTbody) return;
  if (!observations || observations.length === 0) {
    el.historyTbody.innerHTML = `<tr><td colspan="8" class="empty-state">No observations recorded yet.</td></tr>`;
    return;
  }

  const rowsHtml = observations.slice().reverse().map(obs => {
    const t = obs.temperature != null ? obs.temperature.toFixed(1) : '--';
    const h = obs.humidity != null ? obs.humidity.toFixed(1) : '--';
    const action = obs.active_action || 'Sealed Normal';
    const q = obs.data_quality || {};
    const activeSensors = q.active_sensor_count != null ? `${q.active_sensor_count}/9` : '9/9';
    const deltaT = q.inter_sensor_temp_delta != null ? `${q.inter_sensor_temp_delta.toFixed(1)}°C` : '0.0°C';
    const healthBadge = q.has_missing_data
      ? `<span class="badge" style="background: rgba(245,158,11,0.15); color: #f59e0b; border: 1px solid #f59e0b; font-size: 0.7rem;">PARTIAL NaN</span>`
      : `<span class="badge badge-normal" style="font-size: 0.7rem;">COMPLETE</span>`;

    return `
      <tr>
        <td style="font-family: var(--font-mono); font-weight: 600;">${obs.step}</td>
        <td style="font-family: var(--font-mono); color: var(--text-secondary); font-size: 0.75rem;">${formatTimestamp(obs.timestamp)}</td>
        <td style="font-family: var(--font-mono); color: var(--telemetry-sky);">${t}</td>
        <td style="font-family: var(--font-mono); color: var(--telemetry-indigo);">${h}</td>
        <td>${activeSensors}</td>
        <td>${deltaT}</td>
        <td><span style="font-size: 0.75rem; color: ${action.includes('opened') ? '#f59e0b' : '#94a3b8'};">${action}</span></td>
        <td>${healthBadge}</td>
      </tr>
    `;
  }).join('');

  el.historyTbody.innerHTML = rowsHtml;
}

async function refreshOperations() {
  if (isRequestInProgress || isMutatingState) return;
  isRequestInProgress = true;
  const thisGen = ++currentGeneration;

  try {
    const [currentObs, historyRes, playbackRes] = await Promise.all([
      fetchJson(`${API_BASE}/warehouse/current`),
      fetchJson(`${API_BASE}/warehouse/history?limit=25`),
      fetchJson(`${API_BASE}/warehouse/playback`).catch(() => null),
    ]);

    if (thisGen !== currentGeneration) return;

    restoreOnlineStatus();
    renderObservation(currentObs);
    renderHistory(historyRes.observations || []);

    if (playbackRes && el.playbackFill) {
      const pct = playbackRes.progress_percent != null ? playbackRes.progress_percent : 0;
      el.playbackFill.style.width = `${pct}%`;
    }
  } catch (err) {
    if (thisGen === currentGeneration) {
      handleConnectionFailure(err);
    }
  } finally {
    isRequestInProgress = false;
  }
}

async function stepOperations() {
  if (isMutatingState) return;
  isMutatingState = true;
  setControlsDisabled(true);
  if (el.controlStatus) el.controlStatus.textContent = 'Advancing observation...';

  try {
    const res = await fetchJson(`${API_BASE}/warehouse/step`, { method: 'POST' });
    restoreOnlineStatus();
    renderObservation(res.observation);
    await refreshOperations();
    if (el.controlStatus) el.controlStatus.textContent = `Advanced to Step ${res.observation.step}. Evaluated by Defender.`;
  } catch (err) {
    console.error('Failed to advance observation:', err);
    if (el.controlStatus) el.controlStatus.textContent = `Error: ${err.message}`;
  } finally {
    isMutatingState = false;
    setControlsDisabled(false);
  }
}

async function seekPlayback() {
  if (!el.seekInput) return;
  const targetStep = parseInt(el.seekInput.value, 10);
  if (isNaN(targetStep) || targetStep < 0) return;

  isMutatingState = true;
  setControlsDisabled(true);
  if (el.controlStatus) el.controlStatus.textContent = `Seeking to step ${targetStep}...`;

  try {
    const res = await fetchJson(`${API_BASE}/warehouse/seek`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ step: targetStep }),
    });
    restoreOnlineStatus();
    renderObservation(res.observation);
    await refreshOperations();
    if (el.controlStatus) el.controlStatus.textContent = `Jumped to step ${targetStep}. Evaluated by Defender.`;
  } catch (err) {
    console.error('Seek error:', err);
    if (el.controlStatus) el.controlStatus.textContent = `Seek error: ${err.message}`;
  } finally {
    isMutatingState = false;
    setControlsDisabled(false);
  }
}

async function resetOperations() {
  if (isMutatingState) return;
  if (!window.confirm('Reset playback to initial step 0?')) return;

  isMutatingState = true;
  setControlsDisabled(true);
  if (el.controlStatus) el.controlStatus.textContent = 'Resetting data source and defender pipeline...';

  try {
    await fetchJson(`${API_BASE}/warehouse/reset`, { method: 'POST' });
    restoreOnlineStatus();
    await refreshOperations();
    if (el.controlStatus) el.controlStatus.textContent = 'Reset complete. Cursor at Step 0.';
  } catch (err) {
    console.error('Reset error:', err);
    if (el.controlStatus) el.controlStatus.textContent = `Reset error: ${err.message}`;
  } finally {
    isMutatingState = false;
    setControlsDisabled(false);
  }
}

async function toggleDataSourceMode() {
  if (isMutatingState) return;
  isMutatingState = true;
  setControlsDisabled(true);

  try {
    const currentMeta = await fetchJson(`${API_BASE}/warehouse/metadata`);
    const nextMode = currentMeta.is_real_dataset ? 'simulator' : 'hohenheim';
    if (el.controlStatus) el.controlStatus.textContent = `Switching mode to ${nextMode}...`;

    await fetchJson(`${API_BASE}/warehouse/mode/${nextMode}`, { method: 'POST' });
    restoreOnlineStatus();
    await refreshOperations();
    if (el.controlStatus) el.controlStatus.textContent = `Mode switched to ${nextMode}.`;
  } catch (err) {
    console.error('Mode switch error:', err);
    if (el.controlStatus) el.controlStatus.textContent = `Mode switch error: ${err.message}`;
  } finally {
    isMutatingState = false;
    setControlsDisabled(false);
  }
}

function toggleContinuous() {
  isContinuousPlaying = !isContinuousPlaying;
  if (isContinuousPlaying) {
    if (el.txtContinuous) el.txtContinuous.textContent = 'Pause Telemetry';
    if (el.btnContinuous) el.btnContinuous.classList.add('btn-primary');
    continuousTimer = setInterval(() => {
      stepOperations();
    }, 1500);
  } else {
    if (el.txtContinuous) el.txtContinuous.textContent = 'Auto-Play Telemetry';
    if (el.btnContinuous) el.btnContinuous.classList.remove('btn-primary');
    if (continuousTimer) {
      clearInterval(continuousTimer);
      continuousTimer = null;
    }
  }
}

// Initialize Polling
refreshOperations();
setInterval(refreshOperations, POLL_INTERVAL_MS);
