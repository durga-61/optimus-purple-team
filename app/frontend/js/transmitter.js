/**
 * Optimus — Sensor Transmitter Portal Controller
 * Replays authentic University of Hohenheim telemetry (Zenodo 15130001)
 * and transmits validated observations to the Defender pipeline.
 * Data acquisition, playback, and transmission ONLY (zero detection logic).
 */

let currentStep = 0;
let currentObservation = null;
let isPlaying = false;
let playInterval = null;
let isTransmitting = false;

// SENSOR ROLES MAPPING
const TRANSMITTER_SENSOR_ROLES = {
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

// 1. Refresh Observation & Playback State
async function refreshTransmitterState() {
  try {
    const [obs, play] = await Promise.all([
      fetchJson(`${API_BASE}/warehouse/current`),
      fetchJson(`${API_BASE}/warehouse/playback`).catch(() => null),
    ]);

    currentObservation = obs;
    currentStep = obs.step || 0;

    // Update UI elements
    const stepInput = document.getElementById('tx-step-input');
    if (stepInput && document.activeElement !== stepInput) {
      stepInput.value = currentStep;
    }

    const timeEl = document.getElementById('tx-timestamp');
    if (timeEl) timeEl.textContent = formatTimestamp(obs.timestamp);

    const stepBadge = document.getElementById('tx-step-badge');
    if (stepBadge) stepBadge.textContent = `Step ${currentStep} / 156,835`;

    const progressFill = document.getElementById('tx-progress-fill');
    if (progressFill && play) {
      const pct = play.progress_percent != null ? play.progress_percent : 0;
      progressFill.style.width = `${pct.toFixed(2)}%`;
    }

    const actionBadge = document.getElementById('tx-action-badge');
    if (actionBadge) {
      if (obs.active_action === 'Door opened') {
        actionBadge.innerHTML = `<span class="badge badge-suspicious">&bull; Physical Event: Door Opened</span>`;
      } else if (obs.active_action === 'Door closed') {
        actionBadge.innerHTML = `<span class="badge badge-normal">&bull; Physical Event: Door Closed</span>`;
      } else {
        actionBadge.innerHTML = `<span class="badge badge-normal">&bull; Normal Operating Routine</span>`;
      }
    }

    const dq = obs.data_quality || {};
    const deltaTEl = document.getElementById('tx-delta-t');
    if (deltaTEl) deltaTEl.textContent = `ΔT: ${formatNullableNumber(dq.inter_sensor_temp_delta, 1, '°C', '0.0°C')}`;

    const activeCntEl = document.getElementById('tx-active-count');
    if (activeCntEl) activeCntEl.textContent = `${dq.active_sensor_count ?? 6} / ${dq.total_sensors ?? 9} Active`;

    renderSensors(obs.sensors);
    loadWindowTimeSeries(currentStep);
  } catch (err) {
    console.error('Transmitter state refresh failed:', err);
  }
}

// 2. Render 9-Sensor DHT22 Array
function renderSensors(sensors) {
  const matrixEl = document.getElementById('tx-sensor-matrix');
  if (!matrixEl) return;
  if (!sensors) {
    matrixEl.innerHTML = `<div style="color: var(--text-muted); font-size: 0.8rem;">No sensor data available.</div>`;
    return;
  }

  let html = '';
  for (let i = 1; i <= 9; i++) {
    const sId = `SENSOR0${i}`;
    const sData = sensors[sId] || {};
    const t = sData.temperature;
    const h = sData.humidity;
    const isDropout = t == null || h == null;
    const role = TRANSMITTER_SENSOR_ROLES[sId] || 'Storage Zone';

    html += `
      <div class="sensor-card ${isDropout ? 'dropout' : ''}">
        <div class="sensor-header">
          <span style="color: #fff; font-weight: 700;">${sId}</span>
          ${isDropout
            ? `<span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.35); font-size: 0.65rem;">DROPOUT</span>`
            : `<span class="badge badge-normal" style="font-size: 0.65rem;">ONLINE</span>`}
        </div>
        <div style="font-size: 0.68rem; color: var(--text-muted);">${role}</div>
        <div class="sensor-readings" style="margin-top: 0.35rem;">
          <span style="color: #38bdf8;">${t != null ? Number(t).toFixed(1) + ' °C' : '<span style="color:#64748b; font-weight:normal;">-- °C</span>'}</span>
          <span style="color: #818cf8;">${h != null ? Number(h).toFixed(1) + ' %' : '<span style="color:#64748b; font-weight:normal;">-- %</span>'}</span>
        </div>
      </div>
    `;
  }
  matrixEl.innerHTML = html;
}

// 3. Compact Rolling Window Time-Series Visualization (SVG)
async function loadWindowTimeSeries(step, size = 20) {
  const chartEl = document.getElementById('tx-svg-chart');
  if (!chartEl) return;

  try {
    const startStep = Math.max(0, step - 5);
    const res = await fetchJson(`${API_BASE}/warehouse/window?step=${startStep}&size=${size}`);
    const obsList = res.observations || [];
    if (obsList.length === 0) return;

    const width = 450;
    const height = 110;
    const padL = 35;
    const padR = 15;
    const padT = 15;
    const padB = 20;
    const plotW = width - padL - padR;
    const plotH = height - padT - padB;

    const temps = obsList.map(o => o.temperature != null ? o.temperature : 20.0);
    const minT = Math.floor(Math.min(...temps) - 2);
    const maxT = Math.ceil(Math.max(...temps) + 2);
    const rangeT = Math.max(1, maxT - minT);

    const getX = i => padL + (i / Math.max(1, obsList.length - 1)) * plotW;
    const getY = t => padT + plotH - ((t - minT) / rangeT) * plotH;

    let pathD = '';
    obsList.forEach((obs, idx) => {
      const t = obs.temperature != null ? obs.temperature : 20.0;
      const x = getX(idx);
      const y = getY(t);
      pathD += `${idx === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)} `;
    });

    let svg = `
      <line x1="${padL}" y1="${padT}" x2="${padL + plotW}" y2="${padT}" stroke="rgba(255,255,255,0.08)" stroke-width="1" />
      <line x1="${padL}" y1="${padT + plotH/2}" x2="${padL + plotW}" y2="${padT + plotH/2}" stroke="rgba(255,255,255,0.08)" stroke-width="1" />
      <line x1="${padL}" y1="${padT + plotH}" x2="${padL + plotW}" y2="${padT + plotH}" stroke="rgba(255,255,255,0.08)" stroke-width="1" />

      <text x="${padL - 6}" y="${padT + 4}" fill="#64748b" font-size="10" text-anchor="end" font-family="monospace">${maxT}°</text>
      <text x="${padL - 6}" y="${padT + plotH/2 + 3}" fill="#64748b" font-size="10" text-anchor="end" font-family="monospace">${((maxT + minT)/2).toFixed(0)}°</text>
      <text x="${padL - 6}" y="${padT + plotH + 3}" fill="#64748b" font-size="10" text-anchor="end" font-family="monospace">${minT}°</text>

      <path d="${pathD}" fill="none" stroke="#38bdf8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
    `;

    // Highlight current observation point
    const curIdx = obsList.findIndex(o => o.step === step);
    if (curIdx >= 0) {
      const curT = obsList[curIdx].temperature != null ? obsList[curIdx].temperature : 20.0;
      svg += `<circle cx="${getX(curIdx)}" cy="${getY(curT)}" r="4.5" fill="#38bdf8" stroke="#fff" stroke-width="1.5" />`;
    }

    chartEl.innerHTML = svg;
  } catch (err) {
    console.warn('Transmitter time-series chart error:', err);
  }
}

// 4. Playback Navigation Controls
async function txStepForward() {
  try {
    const res = await fetchJson(`${API_BASE}/warehouse/step`, { method: 'POST' });
    currentStep = res.observation.step;
    await refreshTransmitterState();

    const autoTxCheckbox = document.getElementById('auto-transmit-checkbox');
    if (autoTxCheckbox && autoTxCheckbox.checked) {
      await transmitCurrentObservation();
    }
  } catch (err) {
    alert(`Step failed: ${err.message}`);
  }
}

async function txJumpToStep() {
  const input = document.getElementById('tx-step-input');
  if (!input) return;
  const target = parseInt(input.value, 10);
  if (isNaN(target) || target < 0) return;

  try {
    const res = await fetchJson(`${API_BASE}/warehouse/seek`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ step: target }),
    });
    currentStep = res.observation.step;
    await refreshTransmitterState();

    const autoTxCheckbox = document.getElementById('auto-transmit-checkbox');
    if (autoTxCheckbox && autoTxCheckbox.checked) {
      await transmitCurrentObservation();
    }
  } catch (err) {
    alert(`Jump failed: ${err.message}`);
  }
}

async function txResetPlayback() {
  try {
    await fetchJson(`${API_BASE}/warehouse/seek`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ step: 0 }),
    });
    currentStep = 0;
    await refreshTransmitterState();
  } catch (err) {
    alert(`Reset failed: ${err.message}`);
  }
}

function txToggleAutoPlay() {
  const btn = document.getElementById('btn-play-pause');
  if (!btn) return;

  if (isPlaying) {
    isPlaying = false;
    clearInterval(playInterval);
    playInterval = null;
    btn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg> Play (+5s/sec)`;
    btn.className = 'btn';
  } else {
    isPlaying = true;
    btn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="4" width="4" height="16"></rect><rect x="14" y="4" width="4" height="16"></rect></svg> Pause`;
    btn.className = 'btn btn-primary';
    playInterval = setInterval(txStepForward, 1200);
  }
}

// 5. Transmit Observation to Defender Pipeline
async function transmitCurrentObservation() {
  if (isTransmitting) return;
  isTransmitting = true;

  const btn = document.getElementById('btn-transmit');
  if (btn) btn.disabled = true;

  const receiptEl = document.getElementById('tx-receipt-card');
  const logEl = document.getElementById('tx-log-content');

  try {
    const res = await fetchJson(`${API_BASE}/warehouse/transmit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ step: currentStep }),
    });

    if (receiptEl) receiptEl.style.display = 'block';

    const statusBadge = document.getElementById('receipt-status-badge');
    if (statusBadge) {
      statusBadge.textContent = res.status;
      statusBadge.className = 'badge badge-normal';
    }

    const obsIdEl = document.getElementById('receipt-obs-id');
    if (obsIdEl) obsIdEl.textContent = res.observation_id;

    const latencyEl = document.getElementById('receipt-latency');
    if (latencyEl) latencyEl.textContent = `${res.latency_ms.toFixed(1)} ms`;

    const verdictEl = document.getElementById('receipt-verdict');
    if (verdictEl) {
      verdictEl.innerHTML = `<span class="badge ${getBadgeClass(res.defender_classification)}">${res.defender_classification}</span> (Risk: ${res.risk_score.toFixed(3)})`;
    }

    if (logEl) {
      const nowStr = new Date().toISOString().substring(11, 19);
      const entry = `[${nowStr} UTC] TRANSMIT ${res.observation_id} -> Defender: ${res.defender_classification} (Risk: ${res.risk_score.toFixed(3)}, ${res.latency_ms} ms)\n`;
      logEl.textContent = entry + logEl.textContent;
    }
  } catch (err) {
    if (receiptEl) receiptEl.style.display = 'block';
    const statusBadge = document.getElementById('receipt-status-badge');
    if (statusBadge) {
      statusBadge.textContent = 'TRANSMISSION FAILED';
      statusBadge.className = 'badge badge-potential_attack';
    }
    const verdictEl = document.getElementById('receipt-verdict');
    if (verdictEl) verdictEl.textContent = `Error: ${err.message}`;
  } finally {
    isTransmitting = false;
    if (btn) btn.disabled = false;
  }
}

// Initialization
document.addEventListener('DOMContentLoaded', () => {
  refreshTransmitterState();
});
