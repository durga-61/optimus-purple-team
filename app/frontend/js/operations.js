/**
 * Live Operations & Sensor Monitor - Client Application
 * Communicates exclusively with the warehouse simulation endpoints.
 * Displays raw operational records and sensor readings without security evaluations.
 */

const API_BASE = '/api';
const POLL_INTERVAL_MS = 3000;
let isRequestInProgress = false;
let isMutatingState = false;
let currentGeneration = 0;

// DOM Elements
const el = {
  connectionBanner: document.getElementById('connection-banner'),
  backendHealth: document.getElementById('kpi-backend-health'),
  healthDot: document.getElementById('health-dot'),
  currentTime: document.getElementById('current-time'),

  // Section 1: Current Observation
  opsWhId: document.getElementById('ops-wh-id'),
  opsWhStep: document.getElementById('ops-wh-step'),
  opsLastTimestamp: document.getElementById('ops-last-timestamp'),
  currentTemp: document.getElementById('ops-current-temp'),
  currentHum: document.getElementById('ops-current-hum'),
  currentOcc: document.getElementById('ops-current-occ'),
  currentInv: document.getElementById('ops-current-inv'),
  currentFreeCap: document.getElementById('ops-current-free-cap'),
  currentTotalCap: document.getElementById('ops-current-total-cap'),
  currentInbound: document.getElementById('ops-current-inbound'),
  currentOutbound: document.getElementById('ops-current-outbound'),

  // Section 2: Sensor / Operational Metrics
  temp: document.getElementById('ops-temp'),
  humidity: document.getElementById('ops-humidity'),
  occupancy: document.getElementById('ops-occupancy'),
  occupancySub: document.getElementById('ops-occupancy-sub'),
  occupancyBar: document.getElementById('ops-occupancy-bar'),

  inventory: document.getElementById('ops-inventory'),
  freeCapacity: document.getElementById('ops-free-capacity'),
  totalCapacity: document.getElementById('ops-total-capacity'),
  invRatio: document.getElementById('ops-inv-ratio'),
  totalCapRatio: document.getElementById('ops-total-cap-ratio'),
  capBar: document.getElementById('ops-cap-bar'),

  inbound: document.getElementById('ops-inbound'),
  outbound: document.getElementById('ops-outbound'),
  netFlow: document.getElementById('ops-net-flow'),

  // Charts
  chartValTemp: document.getElementById('chart-val-temp'),
  chartSvgTemp: document.getElementById('chart-svg-temp'),
  chartValInv: document.getElementById('chart-val-inv'),
  chartSvgInv: document.getElementById('chart-svg-inv'),
  chartValHum: document.getElementById('chart-val-hum'),
  chartSvgHum: document.getElementById('chart-svg-hum'),
  chartValOcc: document.getElementById('chart-val-occ'),
  chartSvgOcc: document.getElementById('chart-svg-occ'),

  // Section 3: History Table
  historyTbody: document.getElementById('ops-history-tbody'),

  // Section 4: Simulation Controls
  btnStep: document.getElementById('btn-ops-step'),
  btnReset: document.getElementById('btn-ops-reset'),
  controlStatus: document.getElementById('ops-control-status'),
};

// Utilities
function formatTimestamp(isoString) {
  if (!isoString) return '--:--:--';
  try {
    const d = new Date(isoString);
    return d.toTimeString().split(' ')[0];
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
}

function handleConnectionFailure(err) {
  console.error('Failed to communicate with warehouse simulator backend:', err);
  if (el.connectionBanner) el.connectionBanner.classList.remove('hidden');
  if (el.backendHealth) el.backendHealth.textContent = 'OFFLINE (DISCONNECTED)';
  if (el.healthDot) el.healthDot.classList.add('offline');
  document.body.classList.add('backend-offline');
  setControlsDisabled(true);
}

function restoreOnlineStatus() {
  if (el.connectionBanner) el.connectionBanner.classList.add('hidden');
  if (el.backendHealth) el.backendHealth.textContent = 'ONLINE';
  if (el.healthDot) el.healthDot.classList.remove('offline');
  document.body.classList.remove('backend-offline');
  if (!isMutatingState) {
    setControlsDisabled(false);
  }
}

// In-memory operator session token (NOT stored in localStorage for security)
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
    const promptMsg = 'Operator authentication required. Please enter your Operator Token for this session:';
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
        console.warn('Operator session login failed:', loginErr);
      }
      headers['Authorization'] = `Bearer ${inMemoryOperatorToken}`;
      const retryRes = await fetch(url, {
        credentials: 'same-origin',
        headers,
        ...options,
      });
      if (!retryRes.ok) {
        const errBody = await retryRes.text();
        throw new Error(`HTTP ${retryRes.status}: ${errBody}`);
      }
      return await retryRes.json();
    }
  }

  if (!res.ok) {
    const errBody = await res.text();
    throw new Error(`HTTP ${res.status}: ${errBody}`);
  }
  return await res.json();
}

// Lightweight Browser-Native SVG Chart Renderer
function renderSvgChart(svgElement, values, color, unit, padMin = null, padMax = null) {
  if (!svgElement) return;
  if (!values || values.length === 0) {
    svgElement.innerHTML = '<text x="200" y="65" text-anchor="middle" fill="#6b7280" font-size="12">No historical data</text>';
    return;
  }

  const width = 400;
  const height = 130;
  const padLeft = 36;
  const padRight = 16;
  const padTop = 16;
  const padBottom = 24;

  const chartW = width - padLeft - padRight;
  const chartH = height - padTop - padBottom;

  let min = Math.min(...values);
  let max = Math.max(...values);

  if (padMin !== null) min = Math.min(min, padMin);
  if (padMax !== null) max = Math.max(max, padMax);

  if (min === max) {
    min = min - 1;
    max = max + 1;
  } else {
    const buffer = (max - min) * 0.12;
    min -= buffer;
    max += buffer;
  }

  const n = values.length;
  const points = values.map((v, i) => {
    const x = n === 1 ? padLeft + chartW / 2 : padLeft + (i / (n - 1)) * chartW;
    const y = padTop + chartH - ((v - min) / (max - min)) * chartH;
    return { x, y, v };
  });

  const polylinePoints = points.map(p => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');

  // Area under line
  const firstX = points[0].x.toFixed(1);
  const lastX = points[points.length - 1].x.toFixed(1);
  const bottomY = (padTop + chartH).toFixed(1);
  const areaPoints = `${firstX},${bottomY} ${polylinePoints} ${lastX},${bottomY}`;

  // Grid lines
  const midVal = ((min + max) / 2).toFixed(1);
  const midY = (padTop + chartH / 2).toFixed(1);

  let dotsHtml = '';
  if (n <= 30) {
    dotsHtml = points.map(p => `
      <circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="3" fill="${color}" stroke="#0f172a" stroke-width="1.5">
        <title>Value: ${p.v.toFixed(2)}${unit}</title>
      </circle>
    `).join('');
  }

  svgElement.innerHTML = `
    <!-- Horizontal Gridlines -->
    <line x1="${padLeft}" y1="${padTop}" x2="${width - padRight}" y2="${padTop}" stroke="rgba(255,255,255,0.06)" stroke-dasharray="3,3" />
    <line x1="${padLeft}" y1="${midY}" x2="${width - padRight}" y2="${midY}" stroke="rgba(255,255,255,0.06)" stroke-dasharray="3,3" />
    <line x1="${padLeft}" y1="${bottomY}" x2="${width - padRight}" y2="${bottomY}" stroke="rgba(255,255,255,0.12)" />

    <!-- Y-Axis Labels -->
    <text x="${padLeft - 6}" y="${padTop + 4}" fill="#64748b" font-size="9" font-family="monospace" text-anchor="end">${max.toFixed(1)}</text>
    <text x="${padLeft - 6}" y="${midY}" fill="#475569" font-size="9" font-family="monospace" text-anchor="end">${midVal}</text>
    <text x="${padLeft - 6}" y="${bottomY}" fill="#64748b" font-size="9" font-family="monospace" text-anchor="end">${min.toFixed(1)}</text>

    <!-- Gradient Area -->
    <defs>
      <linearGradient id="grad-${color.replace('#', '')}" x1="0%" y1="0%" x2="0%" y2="100%">
        <stop offset="0%" stop-color="${color}" stop-opacity="0.25" />
        <stop offset="100%" stop-color="${color}" stop-opacity="0.0" />
      </linearGradient>
    </defs>
    <polygon points="${areaPoints}" fill="url(#grad-${color.replace('#', '')})" />

    <!-- Trend Line -->
    <polyline points="${polylinePoints}" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />

    <!-- Data Points -->
    ${dotsHtml}
  `;
}

// Render Dashboard Elements
function renderOperationsDashboard(currentObs, historyData) {
  if (!currentObs) return;

  const totalCap = currentObs.capacity || currentObs.total_capacity || 50.0;

  // Section 1: Current Observation
  if (el.opsWhId) el.opsWhId.textContent = currentObs.warehouse || 'W01';
  if (el.opsWhStep) el.opsWhStep.textContent = `Step ${currentObs.step}`;
  if (el.opsLastTimestamp) el.opsLastTimestamp.textContent = `${formatTimestamp(currentObs.timestamp)} UTC`;

  if (el.currentTemp) el.currentTemp.textContent = currentObs.temperature.toFixed(1);
  if (el.currentHum) el.currentHum.textContent = currentObs.humidity.toFixed(1);
  if (el.currentOcc) el.currentOcc.textContent = currentObs.occupancy.toFixed(1);
  if (el.currentInv) el.currentInv.textContent = currentObs.inventory.toFixed(1);
  if (el.currentFreeCap) el.currentFreeCap.textContent = currentObs.free_capacity.toFixed(1);
  if (el.currentTotalCap) el.currentTotalCap.textContent = totalCap.toFixed(1);
  if (el.currentInbound) el.currentInbound.textContent = currentObs.inbound.toFixed(1);
  if (el.currentOutbound) el.currentOutbound.textContent = currentObs.outbound.toFixed(1);

  // Section 2: Sensor / Operational Metrics
  if (el.temp) el.temp.textContent = `${currentObs.temperature.toFixed(1)} °C`;
  if (el.humidity) el.humidity.textContent = `${currentObs.humidity.toFixed(1)} %`;
  if (el.occupancy) el.occupancy.textContent = `${currentObs.occupancy.toFixed(1)} %`;
  if (el.occupancySub) el.occupancySub.textContent = `${currentObs.occupancy.toFixed(1)}%`;
  if (el.occupancyBar) {
    el.occupancyBar.style.width = `${Math.min(100, Math.max(0, currentObs.occupancy))}%`;
  }

  if (el.inventory) el.inventory.textContent = `${currentObs.inventory.toFixed(1)} t`;
  if (el.freeCapacity) el.freeCapacity.textContent = `${currentObs.free_capacity.toFixed(1)} t`;
  if (el.totalCapacity) el.totalCapacity.textContent = `${totalCap.toFixed(1)} t`;
  if (el.invRatio) el.invRatio.textContent = currentObs.inventory.toFixed(1);
  if (el.totalCapRatio) el.totalCapRatio.textContent = totalCap.toFixed(1);

  const invPct = totalCap > 0 ? (currentObs.inventory / totalCap) * 100 : 0;
  if (el.capBar) {
    el.capBar.style.width = `${Math.min(100, Math.max(0, invPct))}%`;
  }

  if (el.inbound) el.inbound.textContent = `${currentObs.inbound.toFixed(1)} t`;
  if (el.outbound) el.outbound.textContent = `${currentObs.outbound.toFixed(1)} t`;
  const net = currentObs.inbound - currentObs.outbound;
  if (el.netFlow) {
    const sign = net > 0 ? '+' : '';
    el.netFlow.textContent = `${sign}${net.toFixed(1)} t`;
    el.netFlow.style.color = net > 0 ? 'var(--telemetry-emerald)' : (net < 0 ? 'var(--telemetry-amber)' : 'var(--text-primary)');
  }

  // Historical Charts & Table
  const observations = (historyData && historyData.observations) ? historyData.observations : [currentObs];

  if (el.chartValTemp) el.chartValTemp.textContent = `${currentObs.temperature.toFixed(1)} °C`;
  if (el.chartValInv) el.chartValInv.textContent = `${currentObs.inventory.toFixed(1)} t`;
  if (el.chartValHum) el.chartValHum.textContent = `${currentObs.humidity.toFixed(1)} %`;
  if (el.chartValOcc) el.chartValOcc.textContent = `${currentObs.occupancy.toFixed(1)} %`;

  const temps = observations.map(o => o.temperature);
  const invs = observations.map(o => o.inventory);
  const hums = observations.map(o => o.humidity);
  const occs = observations.map(o => o.occupancy);

  renderSvgChart(el.chartSvgTemp, temps, '#38bdf8', '°C');
  renderSvgChart(el.chartSvgInv, invs, '#10b981', 't');
  renderSvgChart(el.chartSvgHum, hums, '#818cf8', '%');
  renderSvgChart(el.chartSvgOcc, occs, '#f59e0b', '%');

  // Section 3: History Table (Newest observations at the top)
  if (el.historyTbody) {
    const reversed = [...observations].reverse();
    el.historyTbody.innerHTML = reversed.map((obs, idx) => `
      <tr class="${idx === 0 ? 'row-latest' : ''}">
        <td style="font-weight: 700; color: #fff;">
          Step ${obs.step}
          ${idx === 0 ? '<span class="latest-pill">LATEST</span>' : ''}
        </td>
        <td style="color: var(--text-muted);">${formatTimestamp(obs.timestamp)} UTC</td>
        <td style="color: var(--telemetry-sky); font-weight: 600;">${obs.temperature.toFixed(1)} &deg;C</td>
        <td style="color: var(--telemetry-indigo);">${obs.humidity.toFixed(1)} %</td>
        <td style="color: var(--telemetry-amber);">${obs.occupancy.toFixed(1)} %</td>
        <td style="color: var(--telemetry-emerald); font-weight: 600;">${obs.inventory.toFixed(1)} t</td>
        <td style="color: var(--telemetry-cyan);">${obs.free_capacity.toFixed(1)} t</td>
        <td style="color: var(--telemetry-emerald);">${obs.inbound.toFixed(1)} t</td>
        <td style="color: var(--telemetry-amber);">${obs.outbound.toFixed(1)} t</td>
      </tr>
    `).join('');
  }
}

// Data Fetching Coordinator
async function refreshOperations() {
  if (isRequestInProgress || isMutatingState) return;
  isRequestInProgress = true;
  const gen = currentGeneration;

  try {
    const [currentObs, historyData] = await Promise.all([
      fetchJson(`${API_BASE}/warehouse/current`),
      fetchJson(`${API_BASE}/warehouse/history?limit=50`),
    ]);

    if (gen === currentGeneration && !isMutatingState) {
      restoreOnlineStatus();
      try {
        renderOperationsDashboard(currentObs, historyData);
      } catch (renderErr) {
        console.error('Error rendering operations dashboard:', renderErr);
      }
    }
  } catch (err) {
    handleConnectionFailure(err);
  } finally {
    isRequestInProgress = false;
  }
}

// Operations Actions (Step & Reset)
async function advanceOperationsStep() {
  if (isMutatingState) return;
  isMutatingState = true;
  setControlsDisabled(true);
  currentGeneration++;
  const gen = currentGeneration;

  if (el.controlStatus) {
    el.controlStatus.textContent = 'Advancing simulation by one observation step...';
  }

  try {
    const stepData = await fetchJson(`${API_BASE}/warehouse/step`, { method: 'POST' });
    const historyData = await fetchJson(`${API_BASE}/warehouse/history?limit=50`);

    if (gen === currentGeneration) {
      restoreOnlineStatus();
      try {
        renderOperationsDashboard(stepData.observation, historyData);
        if (el.controlStatus) {
          el.controlStatus.textContent = `Advanced to Step ${stepData.observation.step} (Inventory: ${stepData.observation.inventory.toFixed(1)}t, Temp: ${stepData.observation.temperature.toFixed(1)}°C).`;
        }
      } catch (renderErr) {
        console.error('Error rendering operations dashboard after step:', renderErr);
      }
    }
  } catch (err) {
    handleConnectionFailure(err);
    if (el.controlStatus) {
      el.controlStatus.textContent = `Failed to advance step: ${err.message}`;
    }
    alert(`Failed to advance simulation step: ${err.message}`);
  } finally {
    isMutatingState = false;
    setControlsDisabled(false);
  }
}

async function resetOperationsSimulation() {
  if (isMutatingState) return;
  if (!confirm('Reset warehouse simulation and baseline telemetry?')) return;

  isMutatingState = true;
  setControlsDisabled(true);
  currentGeneration++;
  const gen = currentGeneration;

  if (el.controlStatus) {
    el.controlStatus.textContent = 'Resetting warehouse simulation to initial baseline...';
  }

  try {
    // Reset via warehouse reset endpoint (or security reset alias)
    try {
      await fetchJson(`${API_BASE}/warehouse/reset`, { method: 'POST' });
    } catch (e) {
      await fetchJson(`${API_BASE}/security/reset`, { method: 'POST' });
    }

    const [currentObs, historyData] = await Promise.all([
      fetchJson(`${API_BASE}/warehouse/current`),
      fetchJson(`${API_BASE}/warehouse/history?limit=50`),
    ]);

    if (gen === currentGeneration) {
      restoreOnlineStatus();
      try {
        renderOperationsDashboard(currentObs, historyData);
        if (el.controlStatus) {
          el.controlStatus.textContent = 'Simulation reset to Step 0 baseline.';
        }
      } catch (renderErr) {
        console.error('Error rendering operations dashboard after reset:', renderErr);
      }
    }
  } catch (err) {
    handleConnectionFailure(err);
    if (el.controlStatus) {
      el.controlStatus.textContent = `Failed to reset: ${err.message}`;
    }
    alert(`Failed to reset: ${err.message}`);
  } finally {
    isMutatingState = false;
    setControlsDisabled(false);
  }
}

// Event Listeners
if (el.btnStep) {
  el.btnStep.addEventListener('click', advanceOperationsStep);
}

if (el.btnReset) {
  el.btnReset.addEventListener('click', resetOperationsSimulation);
}

// Start polling
refreshOperations();
setInterval(refreshOperations, POLL_INTERVAL_MS);
