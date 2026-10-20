/**
 * Organization Security Portal - Frontend Client Application
 * Communicates exclusively with the FastAPI backend layer.
 * Zero independent calculations; strictly displays real backend state.
 */

// Configuration
const API_BASE = '/api';
const POLL_INTERVAL_MS = 3000;
let pollTimer = null;
let isRequestInProgress = false;

// DOM Elements
const el = {
  // Connection / Health
  connectionBanner: document.getElementById('connection-banner'),
  backendHealth: document.getElementById('kpi-backend-health'),
  healthIndicatorDot: document.getElementById('health-dot'),
  currentTime: document.getElementById('current-time'),

  // KPIs
  securityStatus: document.getElementById('kpi-security-status'),
  integrityScore: document.getElementById('kpi-integrity-score'),
  activeAlertsCount: document.getElementById('kpi-active-alerts'),
  monitoredSources: document.getElementById('kpi-monitored-sources'),
  lastAnalysisTime: document.getElementById('kpi-last-analysis'),

  // Warehouse Telemetry
  whId: document.getElementById('wh-id'),
  whStep: document.getElementById('wh-step'),
  whInventory: document.getElementById('wh-inventory'),
  whFreeCapacity: document.getElementById('wh-free-capacity'),
  whTotalCapacity: document.getElementById('wh-total-capacity'),
  whOccupancy: document.getElementById('wh-occupancy'),
  whOccupancyBar: document.getElementById('wh-occupancy-bar'),
  whTemperature: document.getElementById('wh-temperature'),
  whHumidity: document.getElementById('wh-humidity'),
  whInbound: document.getElementById('wh-inbound'),
  whOutbound: document.getElementById('wh-outbound'),

  // Pipeline Stages
  stageData: document.getElementById('stage-data'),
  stagePre: document.getElementById('stage-pre'),
  stageMl: document.getElementById('stage-ml'),
  stageSem: document.getElementById('stage-sem'),
  stageTemp: document.getElementById('stage-temp'),
  stageStruct: document.getElementById('stage-struct'),
  stageDec: document.getElementById('stage-dec'),

  // Detailed Analysis
  jointBanner: document.getElementById('joint-decision-banner'),
  jointClass: document.getElementById('joint-classification'),
  jointRisk: document.getElementById('joint-risk'),
  jointIntegrity: document.getElementById('joint-integrity'),
  jointExplanation: document.getElementById('joint-explanation'),

  mlStatus: document.getElementById('ml-status'),
  mlScore: document.getElementById('ml-score'),
  mlFlag: document.getElementById('ml-flag'),
  mlFeatures: document.getElementById('ml-features'),

  semStatus: document.getElementById('sem-status'),
  semScore: document.getElementById('sem-score'),
  c1Block: document.getElementById('c1-block'),
  c2Block: document.getElementById('c2-block'),
  c3Block: document.getElementById('c3-block'),

  tempStatus: document.getElementById('temp-status'),
  tempScore: document.getElementById('temp-score'),
  tempPersistence: document.getElementById('temp-persistence'),
  tempRecurrence: document.getElementById('temp-recurrence'),

  structStatus: document.getElementById('struct-status'),
  structScore: document.getElementById('struct-score'),
  structNodes: document.getElementById('struct-nodes'),
  structEdges: document.getElementById('struct-edges'),

  // Alerts & Events
  alertsContainer: document.getElementById('alerts-container'),
  eventsContainer: document.getElementById('events-container'),

  // Action Buttons
  btnStep: document.getElementById('btn-step'),
  btnReset: document.getElementById('btn-reset'),
  scenariosContainer: document.getElementById('scenarios-container'),
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

function getBadgeClass(status) {
  const norm = (status || 'NORMAL').toLowerCase().replace(/\s+/g, '_');
  if (norm.includes('coordinated')) return 'badge-coordinated_attack';
  if (norm.includes('potential') || norm.includes('violation')) return 'badge-potential_attack';
  if (norm.includes('suspicious') || norm.includes('elevated') || norm.includes('warning')) return 'badge-suspicious';
  if (norm.includes('low') || norm.includes('correlated')) return 'badge-low';
  return 'badge-normal';
}

function updateClock() {
  const now = new Date();
  if (el.currentTime) {
    el.currentTime.textContent = now.toTimeString().split(' ')[0] + ' UTC';
  }
}
setInterval(updateClock, 1000);
updateClock();

// In-memory operator session token (NOT stored in localStorage for security)
let inMemoryOperatorToken = null;

// API Client Functions
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

// Render Functions
function renderDashboard(statusData, warehouseData, latestAnalysis, alerts, events) {
  // 1. Connection Banner
  el.connectionBanner.classList.add('hidden');
  el.backendHealth.textContent = 'ONLINE';
  el.healthIndicatorDot.classList.remove('offline');

  // 2. Security Overview KPIs
  el.securityStatus.innerHTML = `<span class="badge ${getBadgeClass(statusData.status)}">${statusData.status}</span>`;
  el.integrityScore.textContent = `${statusData.integrity_score.toFixed(1)}%`;
  el.activeAlertsCount.textContent = statusData.active_alerts;
  el.monitoredSources.textContent = statusData.sources || 5;
  el.lastAnalysisTime.textContent = formatTimestamp(statusData.last_analysis_timestamp);

  // 3. Live Warehouse Telemetry
  if (warehouseData) {
    el.whId.textContent = warehouseData.warehouse || 'W01';
    el.whStep.textContent = `Step ${warehouseData.step}`;
    el.whInventory.textContent = `${warehouseData.inventory.toFixed(1)} t`;
    el.whFreeCapacity.textContent = `${warehouseData.free_capacity.toFixed(1)} t`;
    el.whTotalCapacity.textContent = `${warehouseData.capacity.toFixed(1)} t`;
    el.whOccupancy.textContent = `${warehouseData.occupancy.toFixed(1)}%`;
    el.whOccupancyBar.style.width = `${Math.min(100, Math.max(0, warehouseData.occupancy))}%`;
    el.whTemperature.textContent = `${warehouseData.temperature.toFixed(1)} °C`;
    el.whHumidity.textContent = `${warehouseData.humidity.toFixed(1)} %`;
    el.whInbound.textContent = `${warehouseData.inbound.toFixed(1)} t`;
    el.whOutbound.textContent = `${warehouseData.outbound.toFixed(1)} t`;
  }

  // 4. Detailed Security Analysis & Pipeline Stages
  if (latestAnalysis) {
    const ml = latestAnalysis.ml;
    const sem = latestAnalysis.semantic;
    const temp = latestAnalysis.temporal;
    const struct = latestAnalysis.structural;
    const dec = latestAnalysis.decision;

    // Pipeline Stages Badges
    el.stageData.innerHTML = `<span class="badge badge-normal">COMPLETED</span>`;
    el.stagePre.innerHTML = `<span class="badge badge-normal">COMPLETED</span>`;
    el.stageMl.innerHTML = `<span class="badge ${getBadgeClass(ml.status)}">${ml.status}</span>`;
    el.stageSem.innerHTML = `<span class="badge ${getBadgeClass(sem.status)}">${sem.status}</span>`;
    el.stageTemp.innerHTML = `<span class="badge ${getBadgeClass(temp.status)}">${temp.status}</span>`;
    el.stageStruct.innerHTML = `<span class="badge ${getBadgeClass(struct.status)}">${struct.status}</span>`;
    el.stageDec.innerHTML = `<span class="badge ${getBadgeClass(dec.classification)}">${dec.classification}</span>`;

    // Joint Decision Banner
    if (el.jointClass) el.jointClass.innerHTML = `<span class="badge ${getBadgeClass(dec.classification)}">${dec.classification}</span>`;
    if (el.jointRisk) el.jointRisk.textContent = `Risk: ${dec.risk_score.toFixed(3)}`;
    if (el.jointIntegrity) el.jointIntegrity.textContent = `Integrity: ${dec.integrity_score.toFixed(1)}%`;
    if (el.jointExplanation) el.jointExplanation.textContent = dec.explanation;

    if (el.jointBanner) {
      if (dec.classification.includes('ATTACK')) {
        el.jointBanner.className = 'decision-banner violation';
      } else if (dec.classification === 'SUSPICIOUS' || dec.classification === 'LOW') {
        el.jointBanner.className = 'decision-banner warning';
      } else {
        el.jointBanner.className = 'decision-banner';
      }
    }

    // ML Card
    el.mlStatus.innerHTML = `<span class="badge ${getBadgeClass(ml.status)}">${ml.status}</span>`;
    el.mlScore.textContent = ml.anomaly_score.toFixed(3);
    el.mlFlag.textContent = ml.is_anomaly ? 'TRUE (Anomaly)' : 'FALSE (Normal)';
    el.mlFeatures.textContent = (ml.features_evaluated || []).join(', ');

    // Semantic Card
    el.semStatus.innerHTML = `<span class="badge ${getBadgeClass(sem.status)}">${sem.status}</span>`;
    el.semScore.textContent = sem.semantic_score.toFixed(2);

    const c1 = (sem.constraints || []).find(c => c.constraint === 'C1');
    const c2 = (sem.constraints || []).find(c => c.constraint === 'C2');
    const c3 = (sem.constraints || []).find(c => c.constraint === 'C3');

    if (c1) {
      el.c1Block.innerHTML = `
        <div class="constraint-header">
          <span>C1: Capacity Consistency</span>
          <span class="badge ${getBadgeClass(c1.status)}">${c1.status}</span>
        </div>
        <div><strong>Expected:</strong> ≤ ${c1.expected}t | <strong>Actual:</strong> ${c1.actual}t | <strong>Diff:</strong> ${c1.difference}t</div>
        <div style="color: var(--text-secondary); font-size: 0.75rem;">${c1.message}</div>
      `;
    }
    if (c2) {
      el.c2Block.innerHTML = `
        <div class="constraint-header">
          <span>C2: Inventory Flow</span>
          <span class="badge ${getBadgeClass(c2.status)}">${c2.status}</span>
        </div>
        <div><strong>Expected:</strong> ${c2.expected}t | <strong>Actual:</strong> ${c2.actual}t | <strong>Diff:</strong> ${c2.difference}t</div>
        <div style="color: var(--text-secondary); font-size: 0.75rem;">${c2.message}</div>
      `;
    }
    if (c3) {
      el.c3Block.innerHTML = `
        <div class="constraint-header">
          <span>C3: Historical Envelope</span>
          <span class="badge ${getBadgeClass(c3.status)}">${c3.status}</span>
        </div>
        <div><strong>Actual:</strong> Temp=${c3.actual.temperature}°C, Hum=${c3.actual.humidity}%</div>
        <div style="color: var(--text-secondary); font-size: 0.75rem;">${c3.message}</div>
      `;
    }

    // Temporal Card
    el.tempStatus.innerHTML = `<span class="badge ${getBadgeClass(temp.status)}">${temp.status}</span>`;
    el.tempScore.textContent = temp.temporal_score.toFixed(2);
    el.tempPersistence.textContent = `${temp.persistence} steps`;
    el.tempRecurrence.textContent = `${temp.recurrence} / ${temp.window_size || 10} window`;

    // Structural Card
    el.structStatus.innerHTML = `<span class="badge ${getBadgeClass(struct.status)}">${struct.status}</span>`;
    el.structScore.textContent = struct.structural_score.toFixed(2);
    el.structNodes.textContent = (struct.affected_nodes || []).length > 0
      ? struct.affected_nodes.join(', ')
      : 'None (Isolated)';
    el.structEdges.textContent = (struct.correlated_edges || []).length > 0
      ? struct.correlated_edges.map(e => e.join(' ↔ ')).join('; ')
      : 'None';
  }

  // 5. Active Alerts
  if (!alerts || alerts.length === 0) {
    el.alertsContainer.innerHTML = `<div class="empty-state">No active security alerts. System is operating normally.</div>`;
  } else {
    el.alertsContainer.innerHTML = alerts.map(a => `
      <div class="alert-item">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <strong style="color: var(--status-attack);">${a.alert_id} &bull; ${a.target}</strong>
          <span class="badge ${getBadgeClass(a.classification)}">${a.severity}</span>
        </div>
        <div style="font-size: 0.85rem; margin-top: 0.2rem;">${a.reason}</div>
        <div style="font-size: 0.75rem; color: var(--text-muted);">${formatTimestamp(a.timestamp)}</div>
      </div>
    `).join('');
  }

  // 6. Security Events Timeline
  if (!events || events.length === 0) {
    el.eventsContainer.innerHTML = `<div class="empty-state">No security events recorded.</div>`;
  } else {
    el.eventsContainer.innerHTML = events.slice().reverse().map(e => `
      <div class="event-row">
        <span class="event-time">${formatTimestamp(e.timestamp)}</span>
        <span class="event-type">${e.event_type}</span>
        <span style="color: var(--text-primary);">${e.message}</span>
      </div>
    `).join('');
  }
}

// Synchronization & Race-Condition Guards
let currentGeneration = 0;
let isMutatingState = false;

function setControlsDisabled(disabled) {
  if (el.btnStep) el.btnStep.disabled = disabled;
  if (el.btnReset) el.btnReset.disabled = disabled;
  const scenarioBtns = el.scenariosContainer ? el.scenariosContainer.querySelectorAll('button') : [];
  scenarioBtns.forEach(btn => btn.disabled = disabled);
}

function handleConnectionFailure(err) {
  console.error('Failed to communicate with security backend:', err);
  el.connectionBanner.classList.remove('hidden');
  el.backendHealth.textContent = 'OFFLINE (DISCONNECTED)';
  el.healthIndicatorDot.classList.add('offline');
  document.body.classList.add('backend-offline');
  if (el.lastAnalysisTime) {
    el.lastAnalysisTime.innerHTML = `<span style="color: var(--status-attack); font-size: 0.85rem;">OFFLINE</span>`;
  }
  setControlsDisabled(true);
}

function restoreOnlineStatus() {
  el.connectionBanner.classList.add('hidden');
  el.backendHealth.textContent = 'ONLINE';
  el.healthIndicatorDot.classList.remove('offline');
  document.body.classList.remove('backend-offline');
  if (!isMutatingState) {
    setControlsDisabled(false);
  }
}

// Data Fetching Coordinator
async function refreshDashboard() {
  if (isRequestInProgress || isMutatingState) return;
  isRequestInProgress = true;
  const gen = currentGeneration;

  try {
    const [statusData, warehouseData, latestAnalysis, alerts, events] = await Promise.all([
      fetchJson(`${API_BASE}/security/status`),
      fetchJson(`${API_BASE}/warehouse/current`),
      fetchJson(`${API_BASE}/security/latest`),
      fetchJson(`${API_BASE}/security/alerts?active_only=true`),
      fetchJson(`${API_BASE}/security/events?limit=30`),
    ]);

    if (gen === currentGeneration && !isMutatingState) {
      restoreOnlineStatus();
      try {
        renderDashboard(statusData, warehouseData, latestAnalysis, alerts, events);
      } catch (renderErr) {
        console.error('Dashboard render error:', renderErr);
      }
    }
  } catch (err) {
    handleConnectionFailure(err);
  } finally {
    isRequestInProgress = false;
  }
}

// User Actions (Atomic Operations)
async function advanceSimulation() {
  if (isMutatingState) return;
  isMutatingState = true;
  setControlsDisabled(true);
  currentGeneration++;
  const gen = currentGeneration;

  try {
    const stepData = await fetchJson(`${API_BASE}/warehouse/step`, { method: 'POST' });
    const [statusData, alerts, events] = await Promise.all([
      fetchJson(`${API_BASE}/security/status`),
      fetchJson(`${API_BASE}/security/alerts?active_only=true`),
      fetchJson(`${API_BASE}/security/events?limit=30`),
    ]);

    if (gen === currentGeneration) {
      restoreOnlineStatus();
      try {
        renderDashboard(statusData, stepData.observation, stepData.security_analysis, alerts, events);
      } catch (renderErr) {
        console.error('Dashboard render error:', renderErr);
      }
    }
  } catch (err) {
    handleConnectionFailure(err);
    alert(`Failed to advance simulation: ${err.message}`);
  } finally {
    isMutatingState = false;
    setControlsDisabled(false);
  }
}

async function resetSimulation() {
  if (isMutatingState) return;
  if (!confirm('Reset warehouse simulation and defender security state to baseline?')) return;

  isMutatingState = true;
  setControlsDisabled(true);
  currentGeneration++;
  const gen = currentGeneration;

  try {
    await fetchJson(`${API_BASE}/security/reset`, { method: 'POST' });
    const [statusData, warehouseData, latestAnalysis, alerts, events] = await Promise.all([
      fetchJson(`${API_BASE}/security/status`),
      fetchJson(`${API_BASE}/warehouse/current`),
      fetchJson(`${API_BASE}/security/latest`),
      fetchJson(`${API_BASE}/security/alerts?active_only=true`),
      fetchJson(`${API_BASE}/security/events?limit=30`),
    ]);

    if (gen === currentGeneration) {
      restoreOnlineStatus();
      try {
        renderDashboard(statusData, warehouseData, latestAnalysis, alerts, events);
      } catch (renderErr) {
        console.error('Dashboard render error:', renderErr);
      }
    }
  } catch (err) {
    handleConnectionFailure(err);
    alert(`Failed to reset: ${err.message}`);
  } finally {
    isMutatingState = false;
    setControlsDisabled(false);
  }
}

async function triggerScenario(scenarioId, btnElement) {
  if (isMutatingState) return;
  isMutatingState = true;
  setControlsDisabled(true);
  currentGeneration++;
  const gen = currentGeneration;

  try {
    const scenarioData = await fetchJson(`${API_BASE}/scenarios/${scenarioId}`, { method: 'POST' });
    const [statusData, alerts, events] = await Promise.all([
      fetchJson(`${API_BASE}/security/status`),
      fetchJson(`${API_BASE}/security/alerts?active_only=true`),
      fetchJson(`${API_BASE}/security/events?limit=30`),
    ]);

    if (gen === currentGeneration) {
      restoreOnlineStatus();
      try {
        renderDashboard(statusData, scenarioData.observation, scenarioData.security_analysis, alerts, events);
      } catch (renderErr) {
        console.error('Dashboard render error:', renderErr);
      }
    }
  } catch (err) {
    handleConnectionFailure(err);
    alert(`Failed to execute scenario '${scenarioId}': ${err.message}`);
  } finally {
    isMutatingState = false;
    setControlsDisabled(false);
  }
}

async function loadScenariosList() {
  try {
    const res = await fetchJson(`${API_BASE}/scenarios`);
    if (!res.scenarios || !el.scenariosContainer) return;

    el.scenariosContainer.innerHTML = res.scenarios.map(s => `
      <button class="btn btn-danger" onclick="triggerScenario('${s.id}', this)" title="${s.description}">
        <span>&#9888;</span> ${s.name}
      </button>
    `).join('');
  } catch (err) {
    console.error('Failed to load scenarios catalog:', err);
  }
}

// Initialization
document.addEventListener('DOMContentLoaded', () => {
  if (el.btnStep) el.btnStep.addEventListener('click', advanceSimulation);
  if (el.btnReset) el.btnReset.addEventListener('click', resetSimulation);

  loadScenariosList();
  refreshDashboard();

  // Start polling
  pollTimer = setInterval(refreshDashboard, POLL_INTERVAL_MS);
});
