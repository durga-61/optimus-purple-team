/**
 * Optimus — Cold-Storage Security Monitor & Attack Evaluation Platform
 * Frontend Client Application.
 *
 * Implements the Three-Area Product Architecture:
 * 1. Experiment Dashboard (Dataset Window, Controlled Attack Injection, Immediate Evaluation)
 * 2. Detection Evidence (Explainable Layer Contributions, Constraints, Audit Proofs)
 * 3. Experiment History & Evaluation (Benchmark Metrics, Reproducibility, CSV Export)
 */

const API_BASE = '/api';
const POLL_INTERVAL_MS = 3000;
let pollTimer = null;
let isRequestInProgress = false;
let isMutatingState = false;
let activeTab = 'dashboard';

// Active Experiment State
let currentStep = 0;
let currentWindowObservations = [];
let currentObservationData = null;
let lastExperimentResult = null;

// SENSOR ROLES MAPPING
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

// SCENARIO DESCRIPTIONS & DEFAULTS
const SCENARIO_DEFAULTS = {
  'temperature_manipulation': {
    desc: 'Applies a discrete numerical offset to a selected sensor channel, testing single-point out-of-envelope detection.',
    paramGroup: 'group-magnitude',
    label: 'Temperature Offset Magnitude (°C)',
    defaultVal: 12.0,
    unit: '°C',
  },
  'humidity_manipulation': {
    desc: 'Alters relative humidity in a selected sensor channel, testing environmental moisture bounds and multi-sensor drift.',
    paramGroup: 'group-magnitude',
    label: 'Humidity Offset Magnitude (%)',
    defaultVal: 25.0,
    unit: '%',
  },
  'sensor_drift': {
    desc: 'Applies a gradual cumulative offset over consecutive observation intervals, evaluating temporal recurrence and subtle evasion.',
    paramGroup: 'group-drift-steps',
    label: 'Drift Rate (°C/step)',
    defaultVal: 0.8,
    unit: '°C/step',
  },
  'replay_substitution': {
    desc: 'Substitutes recorded telemetry from an earlier timestamp under the current timestamp, evaluating temporal continuity and state freezing.',
    paramGroup: 'group-replay-step',
    label: 'Replay Source Step Index',
    defaultVal: 0,
    unit: 'step',
  },
  'cross_sensor_inconsistency': {
    desc: 'Injects an localized thermal gradient into one sensor relative to the remaining spatial array, triggering C4 spatial delta alerts.',
    paramGroup: 'group-magnitude',
    label: 'Spatial Gradient Magnitude (°C)',
    defaultVal: 8.0,
    unit: '°C',
  },
  'sensor_dropout': {
    desc: 'Selectively suppresses telemetry from specified sensor channels, testing missing-data robustness and dropout differentiation.',
    paramGroup: null,
    label: null,
    defaultVal: null,
    unit: null,
  },
};

// DOM Elements
const el = {
  // Navigation Tabs & Panes
  tabDashboard: document.getElementById('tab-dashboard'),
  tabEvidence: document.getElementById('tab-evidence'),
  tabHistory: document.getElementById('tab-history'),
  paneDashboard: document.getElementById('pane-dashboard'),
  paneEvidence: document.getElementById('pane-evidence'),
  paneHistory: document.getElementById('pane-history'),

  // Header & Health
  connectionBanner: document.getElementById('connection-banner'),
  backendHealth: document.getElementById('kpi-backend-health'),
  healthIndicatorDot: document.getElementById('health-dot'),
  currentTime: document.getElementById('current-time'),

  // Provenance & Playback Banner
  sourceNoticeBanner: document.getElementById('source-notice-banner'),
  sourceDescription: document.getElementById('source-description'),
  sourceBadge: document.getElementById('source-badge'),
  actionBadgeContainer: document.getElementById('action-badge-container'),
  playbackFill: document.getElementById('playback-fill'),

  // Area 1: Dataset & Telemetry
  whId: document.getElementById('wh-id'),
  whStep: document.getElementById('wh-step'),
  seekStepInput: document.getElementById('ops-seek-step'),
  btnSeek: document.getElementById('btn-seek'),
  btnStep: document.getElementById('btn-step'),
  btnReset: document.getElementById('btn-reset'),
  btnToggleMode: document.getElementById('btn-toggle-mode'),
  whTimestamp: document.getElementById('wh-timestamp'),
  whTemperature: document.getElementById('wh-temperature'),
  whHumidity: document.getElementById('wh-humidity'),
  whDeltaT: document.getElementById('wh-delta-t'),
  whActiveSensors: document.getElementById('wh-active-sensors'),
  whSpatialDeltaBadge: document.getElementById('wh-spatial-delta-badge'),
  sensorMatrix: document.getElementById('sensor-matrix'),
  svgWindowChart: document.getElementById('svg-window-chart'),

  // Area 1: Attack Configuration
  attackScenarioSelect: document.getElementById('attack-scenario-select'),
  attackTargetSensorSelect: document.getElementById('attack-target-sensor-select'),
  attackMagnitudeInput: document.getElementById('attack-magnitude-input'),
  attackDriftStepsInput: document.getElementById('attack-drift-steps-input'),
  attackReplayStepInput: document.getElementById('attack-replay-step-input'),
  groupMagnitude: document.getElementById('group-magnitude'),
  groupDriftSteps: document.getElementById('group-drift-steps'),
  groupReplayStep: document.getElementById('group-replay-step'),
  labelMagnitude: document.getElementById('label-magnitude'),
  attackScenarioDesc: document.getElementById('attack-scenario-desc'),
  attackDiffTbody: document.getElementById('attack-diff-tbody'),

  // Area 1: Experiment Controls & Results
  btnRunBaseline: document.getElementById('btn-run-baseline'),
  btnRunAttack: document.getElementById('btn-run-attack'),
  btnResetExp: document.getElementById('btn-reset-exp'),
  playbackStatusMsg: document.getElementById('playback-status-msg'),
  resOutcomePill: document.getElementById('res-outcome-pill'),
  resOutcomeText: document.getElementById('res-outcome-text'),
  resExpectedLabel: document.getElementById('res-expected-label'),
  resPredictedClass: document.getElementById('res-predicted-class'),
  resRiskScore: document.getElementById('res-risk-score'),
  resLatencyMs: document.getElementById('res-latency-ms'),
  resModifiedCount: document.getElementById('res-modified-count'),
  resContributingLayers: document.getElementById('res-contributing-layers'),

  // Area 2: Detection Evidence
  evidenceExpId: document.getElementById('evidence-exp-id'),
  evidenceTimestamp: document.getElementById('evidence-timestamp'),
  jointDecisionBanner: document.getElementById('joint-decision-banner'),
  jointClassification: document.getElementById('joint-classification'),
  jointRisk: document.getElementById('joint-risk'),
  jointIntegrity: document.getElementById('joint-integrity'),
  jointExplanation: document.getElementById('joint-explanation'),

  mlStatus: document.getElementById('ml-status'),
  mlScore: document.getElementById('ml-score'),
  mlFlag: document.getElementById('ml-flag'),
  mlMode: document.getElementById('ml-mode'),
  mlFeatures: document.getElementById('ml-features'),

  semStatus: document.getElementById('sem-status'),
  semScore: document.getElementById('sem-score'),
  c1Block: document.getElementById('c1-block'),
  c2Block: document.getElementById('c2-block'),
  c3Block: document.getElementById('c3-block'),
  c4Block: document.getElementById('c4-block'),

  tempStatus: document.getElementById('temp-status'),
  tempScore: document.getElementById('temp-score'),
  tempPersistence: document.getElementById('temp-persistence'),
  tempRecurrence: document.getElementById('temp-recurrence'),

  structStatus: document.getElementById('struct-status'),
  structScore: document.getElementById('struct-score'),
  structNodes: document.getElementById('struct-nodes'),
  structEdges: document.getElementById('struct-edges'),

  kpiAuditChain: document.getElementById('kpi-audit-chain'),
  auditValidStatus: document.getElementById('audit-valid-status'),
  auditEventsCount: document.getElementById('audit-events-count'),
  auditLatestHash: document.getElementById('audit-latest-hash'),

  rawEvidenceJson: document.getElementById('raw-evidence-json'),
  rawEvidenceToggleIcon: document.getElementById('raw-evidence-toggle-icon'),
  expandableRawBody: document.getElementById('expandable-raw-body'),

  // Area 3: Experiment History & Benchmark Evaluation
  metricTotalRuns: document.getElementById('metric-total-runs'),
  metricTp: document.getElementById('metric-tp'),
  metricTn: document.getElementById('metric-tn'),
  metricFp: document.getElementById('metric-fp'),
  metricFn: document.getElementById('metric-fn'),
  metricPrecision: document.getElementById('metric-precision'),
  metricRecall: document.getElementById('metric-recall'),
  metricF1: document.getElementById('metric-f1'),
  metricFpr: document.getElementById('metric-fpr'),
  metricAvgLatency: document.getElementById('metric-avg-latency'),

  filterScenario: document.getElementById('filter-scenario'),
  filterSensor: document.getElementById('filter-sensor'),
  filterOutcome: document.getElementById('filter-outcome'),
  historyTbody: document.getElementById('history-tbody'),

  // Compatibility Hooks
  kpiSecurityStatus: document.getElementById('kpi-security-status'),
  kpiIntegrityScore: document.getElementById('kpi-integrity-score'),
  kpiActiveAlerts: document.getElementById('kpi-active-alerts'),
  whInventory: document.getElementById('wh-inventory'),
  whFreeCapacity: document.getElementById('wh-free-capacity'),
  stageSem: document.getElementById('stage-sem'),
  alertsContainer: document.getElementById('alerts-container'),
  eventsContainer: document.getElementById('events-container'),
};

// Utilities
function formatTimestamp(isoString) {
  if (!isoString) return '--:--:--';
  try {
    const d = new Date(isoString);
    return d.toTimeString().split(' ')[0] + ' UTC';
  } catch (e) {
    return isoString;
  }
}

function formatNullableNumber(val, decimals = 1, unit = '', naText = 'N/A') {
  if (val === null || val === undefined || isNaN(val)) return naText;
  const num = Number(val);
  return `${num.toFixed(decimals)}${unit ? ' ' + unit : ''}`;
}

function getBadgeClass(status) {
  const norm = (status || 'NORMAL').toLowerCase().replace(/\s+/g, '_');
  if (norm.includes('coordinated')) return 'badge-coordinated_attack';
  if (norm.includes('potential') || norm.includes('violation')) return 'badge-potential_attack';
  if (norm.includes('suspicious') || norm.includes('elevated') || norm.includes('warning')) return 'badge-suspicious';
  if (norm.includes('low') || norm.includes('correlated')) return 'badge-low';
  if (norm.includes('not_applicable') || norm === 'na' || norm === 'n/a') return 'badge-na';
  if (norm.includes('insufficient')) return 'badge-insufficient_data';
  return 'badge-normal';
}

function getOutcomeClass(outcome) {
  switch (outcome) {
    case 'TRUE_POSITIVE': return 'outcome-tp';
    case 'TRUE_NEGATIVE': return 'outcome-tn';
    case 'FALSE_POSITIVE': return 'outcome-fp';
    case 'FALSE_NEGATIVE': return 'outcome-fn';
    default: return 'outcome-tn';
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
      headers['Authorization'] = `Bearer ${inMemoryOperatorToken}`;
      const retryRes = await fetch(url, { credentials: 'same-origin', headers, ...options });
      if (!retryRes.ok) {
        throw new Error(`HTTP ${retryRes.status}: ${await retryRes.text()}`);
      }
      return await retryRes.json();
    }
  }

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`HTTP ${res.status}: ${errText}`);
  }
  return await res.json();
}

// Tab Switching
function switchTab(tabName) {
  activeTab = tabName;
  ['dashboard', 'evidence', 'history'].forEach(t => {
    const tabBtn = document.getElementById(`tab-${t}`);
    const pane = document.getElementById(`pane-${t}`);
    if (t === tabName) {
      if (tabBtn) tabBtn.classList.add('active');
      if (pane) pane.classList.add('active');
    } else {
      if (tabBtn) tabBtn.classList.remove('active');
      if (pane) pane.classList.remove('active');
    }
  });

  if (tabName === 'history') {
    loadExperimentHistory();
  }
}

// Render 9-Sensor Matrix Grid
function renderSensorMatrix(sensors) {
  if (!el.sensorMatrix) return;
  if (!sensors || Object.keys(sensors).length === 0) {
    el.sensorMatrix.innerHTML = `<div style="color: var(--text-muted); font-size: 0.8rem; padding: 0.5rem;">Sensor array telemetry not available.</div>`;
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
            ? `<span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.35); font-size: 0.65rem;">DROPOUT</span>`
            : `<span class="badge badge-normal" style="font-size: 0.65rem;">ONLINE</span>`}
        </div>
        <div style="font-size: 0.68rem; color: var(--text-muted);">${role}</div>
        <div class="sensor-readings" style="margin-top: 0.2rem;">
          <span style="color: #38bdf8;">${t != null ? Number(t).toFixed(1) + '°C' : '<span style="color:#64748b; font-weight:normal;">-- °C</span>'}</span>
          <span style="color: #818cf8;">${h != null ? Number(h).toFixed(1) + '%' : '<span style="color:#64748b; font-weight:normal;">-- %</span>'}</span>
        </div>
      </div>
    `;
  }
  el.sensorMatrix.innerHTML = html;
}

// Render Window Time-Series Chart (SVG)
function renderWindowChart(observations, modifiedStep = null, modifiedTemp = null) {
  if (!el.svgWindowChart || !observations || observations.length === 0) return;

  const width = 450;
  const height = 110;
  const padLeft = 35;
  const padRight = 15;
  const padTop = 15;
  const padBottom = 20;

  const plotW = width - padLeft - padRight;
  const plotH = height - padTop - padBottom;

  const temps = observations.map(o => o.temperature != null ? o.temperature : 20.0);
  const minTemp = Math.floor(Math.min(...temps, modifiedTemp != null ? modifiedTemp : 20.0) - 2);
  const maxTemp = Math.ceil(Math.max(...temps, modifiedTemp != null ? modifiedTemp : 20.0) + 2);
  const tempRange = Math.max(1, maxTemp - minTemp);

  // Coordinate mapper
  const getX = i => padLeft + (i / Math.max(1, observations.length - 1)) * plotW;
  const getY = t => padTop + plotH - ((t - minTemp) / tempRange) * plotH;

  // Build baseline path
  let pathD = '';
  observations.forEach((obs, idx) => {
    const t = obs.temperature != null ? obs.temperature : 20.0;
    const x = getX(idx);
    const y = getY(t);
    pathD += `${idx === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)} `;
  });

  // SVG grid lines and axis ticks
  let gridSvg = `
    <line x1="${padLeft}" y1="${padTop}" x2="${padLeft + plotW}" y2="${padTop}" stroke="rgba(255,255,255,0.08)" stroke-width="1" />
    <line x1="${padLeft}" y1="${padTop + plotH / 2}" x2="${padLeft + plotW}" y2="${padTop + plotH / 2}" stroke="rgba(255,255,255,0.08)" stroke-width="1" />
    <line x1="${padLeft}" y1="${padTop + plotH}" x2="${padLeft + plotW}" y2="${padTop + plotH}" stroke="rgba(255,255,255,0.08)" stroke-width="1" />
    <text x="${padLeft - 5}" y="${padTop + 4}" fill="#64748b" font-size="9" text-anchor="end">${maxTemp}°</text>
    <text x="${padLeft - 5}" y="${padTop + plotH / 2 + 3}" fill="#64748b" font-size="9" text-anchor="end">${((maxTemp + minTemp) / 2).toFixed(0)}°</text>
    <text x="${padLeft - 5}" y="${padTop + plotH}" fill="#64748b" font-size="9" text-anchor="end">${minTemp}°</text>
  `;

  // Baseline polyline
  let linesSvg = `<path d="${pathD}" fill="none" stroke="#38bdf8" stroke-width="2" />`;

  // If an attack modified the target observation, plot the modified outlier point / dashed anomaly
  let modSvg = '';
  if (modifiedStep != null && modifiedTemp != null) {
    const targetIdx = observations.findIndex(o => o.step === modifiedStep);
    const idx = targetIdx !== -1 ? targetIdx : 0;
    const x = getX(idx);
    const yOrig = getY(observations[idx].temperature || 20.0);
    const yMod = getY(modifiedTemp);

    modSvg = `
      <line x1="${x.toFixed(1)}" y1="${yOrig.toFixed(1)}" x2="${x.toFixed(1)}" y2="${yMod.toFixed(1)}" stroke="#ef4444" stroke-width="2" stroke-dasharray="3,3" />
      <circle cx="${x.toFixed(1)}" cy="${yMod.toFixed(1)}" r="4" fill="#ef4444" stroke="#fff" stroke-width="1.5" />
      <text x="${x + 6}" y="${yMod - 4}" fill="#ef4444" font-size="9" font-weight="bold">${modifiedTemp.toFixed(1)}°C (Attack)</text>
    `;
  }

  // X-axis timestamps
  const firstTime = observations[0].timestamp ? observations[0].timestamp.substring(11, 19) : 'T0';
  const lastTime = observations[observations.length - 1].timestamp ? observations[observations.length - 1].timestamp.substring(11, 19) : 'TN';
  const axisSvg = `
    <text x="${padLeft}" y="${height - 4}" fill="#64748b" font-size="9" text-anchor="start">${firstTime}</text>
    <text x="${padLeft + plotW}" y="${height - 4}" fill="#64748b" font-size="9" text-anchor="end">${lastTime}</text>
  `;

  el.svgWindowChart.innerHTML = gridSvg + linesSvg + modSvg + axisSvg;
}

// Refresh Playback & Observation State
async function refreshDatasetState() {
  try {
    const [obs, play] = await Promise.all([
      fetchJson(`${API_BASE}/warehouse/current`),
      fetchJson(`${API_BASE}/warehouse/playback`).catch(() => null),
    ]);

    currentObservationData = obs;
    currentStep = obs.step;

    if (el.whId) el.whId.textContent = obs.warehouse || 'W01';
    if (el.whStep) el.whStep.textContent = `Step ${obs.step}`;
    if (el.seekStepInput && document.activeElement !== el.seekStepInput) {
      el.seekStepInput.value = obs.step;
    }
    if (el.whTimestamp) el.whTimestamp.textContent = formatTimestamp(obs.timestamp);

    if (el.whTemperature) el.whTemperature.textContent = formatNullableNumber(obs.temperature, 1, '°C');
    if (el.whHumidity) el.whHumidity.textContent = formatNullableNumber(obs.humidity, 1, '%');

    const dq = obs.data_quality || {};
    if (el.whDeltaT) el.whDeltaT.textContent = formatNullableNumber(dq.inter_sensor_temp_delta, 1, '°C', '0.0 °C');
    if (el.whActiveSensors) el.whActiveSensors.textContent = `${dq.active_sensor_count ?? 9} / ${dq.total_sensors ?? 9} Active`;
    if (el.whSpatialDeltaBadge) el.whSpatialDeltaBadge.textContent = `ΔT: ${formatNullableNumber(dq.inter_sensor_temp_delta, 1, '°C', '0.0°C')}`;

    if (el.sourceBadge) {
      const isReal = obs.is_recorded_playback || obs.source === 'hohenheim';
      el.sourceBadge.textContent = isReal ? 'RECORDED PLAYBACK' : 'SYNTHETIC SIMULATOR';
      el.sourceBadge.className = isReal ? 'badge badge-normal' : 'badge badge-low';
    }

    if (play && el.playbackFill) {
      const pct = play.progress_percent != null ? play.progress_percent : 0;
      el.playbackFill.style.width = `${pct.toFixed(2)}%`;
    }

    if (el.actionBadgeContainer) {
      if (obs.active_action === 'Door opened') {
        el.actionBadgeContainer.innerHTML = `<span class="action-badge action-door-open">&bull; Door Opened Event</span>`;
      } else if (obs.active_action === 'Door closed') {
        el.actionBadgeContainer.innerHTML = `<span class="action-badge action-door-closed">&bull; Door Closed</span>`;
      } else {
        el.actionBadgeContainer.innerHTML = '';
      }
    }

    renderSensorMatrix(obs.sensors);
    updateDiffPreview();

    // Fetch window for chart
    loadWindowTimeSeries(obs.step);
  } catch (err) {
    console.error('Failed to refresh dataset state:', err);
    if (el.connectionBanner) el.connectionBanner.classList.remove('hidden');
    if (el.backendHealth) el.backendHealth.textContent = 'OFFLINE';
  }
}

async function loadWindowTimeSeries(step, size = 20) {
  try {
    const res = await fetchJson(`${API_BASE}/warehouse/window?step=${Math.max(0, step - 5)}&size=${size}`);
    currentWindowObservations = res.observations || [];
    renderWindowChart(currentWindowObservations);
  } catch (err) {
    console.warn('Could not load time-series window:', err);
  }
}

// Scenario Configuration Form Handling
function onScenarioChanged() {
  const sc = el.attackScenarioSelect.value;
  const cfg = SCENARIO_DEFAULTS[sc] || SCENARIO_DEFAULTS['temperature_manipulation'];

  if (el.attackScenarioDesc) {
    el.attackScenarioDesc.textContent = cfg.desc;
  }

  // Manage visibility of parameter groups
  if (el.groupMagnitude) {
    el.groupMagnitude.style.display = cfg.paramGroup === 'group-magnitude' ? 'flex' : 'none';
    if (cfg.label && el.labelMagnitude) el.labelMagnitude.textContent = cfg.label;
    if (cfg.defaultVal !== null && el.attackMagnitudeInput) el.attackMagnitudeInput.value = cfg.defaultVal;
  }
  if (el.groupDriftSteps) {
    el.groupDriftSteps.style.display = cfg.paramGroup === 'group-drift-steps' ? 'flex' : 'none';
  }
  if (el.groupReplayStep) {
    el.groupReplayStep.style.display = cfg.paramGroup === 'group-replay-step' ? 'flex' : 'none';
  }

  updateDiffPreview();
}

function updateDiffPreview() {
  if (!el.attackDiffTbody || !currentObservationData) return;

  const sc = el.attackScenarioSelect ? el.attackScenarioSelect.value : 'temperature_manipulation';
  const targetSensor = el.attackTargetSensorSelect ? el.attackTargetSensorSelect.value : 'SENSOR01';
  const sData = (currentObservationData.sensors || {})[targetSensor] || { temperature: 21.2, humidity: 62.5 };

  const origTemp = sData.temperature != null ? sData.temperature : 21.2;
  const origHum = sData.humidity != null ? sData.humidity : 62.5;

  let propName = 'Temperature';
  let origValStr = `${origTemp.toFixed(1)} °C`;
  let modValStr = '--';
  let deltaStr = '--';

  if (sc === 'temperature_manipulation') {
    const mag = parseFloat(el.attackMagnitudeInput.value) || 12.0;
    const modTemp = origTemp + mag;
    modValStr = `${modTemp.toFixed(1)} °C`;
    deltaStr = `${mag >= 0 ? '+' : ''}${mag.toFixed(1)} °C`;
  } else if (sc === 'humidity_manipulation') {
    propName = 'Humidity';
    origValStr = `${origHum.toFixed(1)} %`;
    const mag = parseFloat(el.attackMagnitudeInput.value) || 25.0;
    const modHum = Math.min(100, Math.max(0, origHum + mag));
    modValStr = `${modHum.toFixed(1)} %`;
    deltaStr = `${mag >= 0 ? '+' : ''}${mag.toFixed(1)} %`;
  } else if (sc === 'sensor_drift') {
    const steps = parseInt(el.attackDriftStepsInput.value, 10) || 5;
    const rate = 0.8;
    const totalDrift = rate * steps;
    const modTemp = origTemp + totalDrift;
    modValStr = `${modTemp.toFixed(1)} °C`;
    deltaStr = `+${totalDrift.toFixed(1)} °C (${steps} steps × 0.8°)`;
  } else if (sc === 'replay_substitution') {
    const replayStep = parseInt(el.attackReplayStepInput.value, 10) || 0;
    modValStr = `Replayed from Step ${replayStep}`;
    deltaStr = `Telemetry Frozen / Replaced`;
  } else if (sc === 'cross_sensor_inconsistency') {
    const mag = parseFloat(el.attackMagnitudeInput.value) || 8.0;
    const modTemp = origTemp + mag;
    modValStr = `${modTemp.toFixed(1)} °C`;
    deltaStr = `+${mag.toFixed(1)} °C (Gradient Violation)`;
  } else if (sc === 'sensor_dropout') {
    propName = 'All Telemetry';
    origValStr = 'Online Readings';
    modValStr = 'Suppressed (Dropout)';
    deltaStr = 'Intentional Dropout';
  }

  el.attackDiffTbody.innerHTML = `
    <tr>
      <td style="font-weight: 700;">${targetSensor}</td>
      <td>${propName}</td>
      <td class="diff-orig">${origValStr}</td>
      <td class="diff-mod">${modValStr}</td>
      <td style="color: #38bdf8; font-weight: 600;">${deltaStr}</td>
    </tr>
  `;
}

// User Actions: Step, Seek, Reset, Mode Toggle
async function jumpToStep() {
  if (isMutatingState || !el.seekStepInput) return;
  const targetStep = parseInt(el.seekStepInput.value, 10);
  if (isNaN(targetStep) || targetStep < 0) return;

  isMutatingState = true;
  setControlsDisabled(true);
  try {
    await fetchJson(`${API_BASE}/warehouse/seek`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ step: targetStep }),
    });
    await refreshDatasetState();
  } catch (err) {
    alert(`Failed to seek: ${err.message}`);
  } finally {
    isMutatingState = false;
    setControlsDisabled(false);
  }
}

async function stepObservation() {
  if (isMutatingState) return;
  isMutatingState = true;
  setControlsDisabled(true);
  try {
    await fetchJson(`${API_BASE}/warehouse/step`, { method: 'POST' });
    await refreshDatasetState();
  } catch (err) {
    alert(`Failed to step: ${err.message}`);
  } finally {
    isMutatingState = false;
    setControlsDisabled(false);
  }
}

async function resetPlaybackCursor() {
  if (isMutatingState) return;
  isMutatingState = true;
  setControlsDisabled(true);
  try {
    await fetchJson(`${API_BASE}/warehouse/reset`, { method: 'POST' });
    await refreshDatasetState();
  } catch (err) {
    alert(`Failed to reset cursor: ${err.message}`);
  } finally {
    isMutatingState = false;
    setControlsDisabled(false);
  }
}

async function toggleDataMode() {
  if (isMutatingState) return;
  isMutatingState = true;
  setControlsDisabled(true);
  try {
    const meta = await fetchJson(`${API_BASE}/warehouse/metadata`);
    const nextMode = meta.is_real_dataset ? 'simulator' : 'hohenheim';
    await fetchJson(`${API_BASE}/warehouse/mode/${nextMode}`, { method: 'POST' });
    await refreshDatasetState();
  } catch (err) {
    alert(`Mode switch failed: ${err.message}`);
  } finally {
    isMutatingState = false;
    setControlsDisabled(false);
  }
}

// Experiment Runner Actions
async function executeBaseline() {
  if (isMutatingState) return;
  isMutatingState = true;
  setControlsDisabled(true);
  if (el.playbackStatusMsg) el.playbackStatusMsg.textContent = 'Evaluating authentic baseline observation with Defender pipeline...';

  try {
    const res = await fetchJson(`${API_BASE}/experiments/baseline`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ step: currentStep }),
    });

    displayExperimentResult(res);
    renderEvidence(res.security_analysis, res);
    if (el.playbackStatusMsg) el.playbackStatusMsg.textContent = `Baseline evaluation completed (${res.experiment_id}). Ground truth: NORMAL, Defender: ${res.defender_prediction}.`;
  } catch (err) {
    alert(`Baseline evaluation failed: ${err.message}`);
    if (el.playbackStatusMsg) el.playbackStatusMsg.textContent = `Error: ${err.message}`;
  } finally {
    isMutatingState = false;
    setControlsDisabled(false);
  }
}

async function executeAttackExperiment() {
  if (isMutatingState) return;
  isMutatingState = true;
  setControlsDisabled(true);
  if (el.playbackStatusMsg) el.playbackStatusMsg.textContent = 'Injecting attack transformation and evaluating with Defender pipeline...';

  try {
    const sc = el.attackScenarioSelect.value;
    const target = el.attackTargetSensorSelect.value;
    const mag = parseFloat(el.attackMagnitudeInput.value);
    const driftSteps = parseInt(el.attackDriftStepsInput.value, 10);
    const replayStep = parseInt(el.attackReplayStepInput.value, 10);

    const config = {
      scenario: sc,
      target_sensor: target,
      magnitude: !isNaN(mag) ? mag : null,
      drift_rate: 0.8,
      drift_steps: !isNaN(driftSteps) ? driftSteps : 5,
      replay_step: !isNaN(replayStep) ? replayStep : 0,
      seed: 42,
    };

    const res = await fetchJson(`${API_BASE}/experiments/attack`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        step: currentStep,
        configuration: config,
      }),
    });

    displayExperimentResult(res);
    renderEvidence(res.security_analysis, res);

    // Plot anomaly on SVG chart
    if (res.modified_fields && res.modified_fields.length > 0) {
      const firstMod = res.modified_fields[0];
      if (firstMod.modified_value != null) {
        renderWindowChart(currentWindowObservations, res.step, firstMod.modified_value);
      }
    }

    if (el.playbackStatusMsg) {
      el.playbackStatusMsg.textContent = `Attack experiment completed (${res.experiment_id}). Ground truth: ATTACK, Defender: ${res.defender_prediction}, Outcome: ${res.outcome}.`;
    }
  } catch (err) {
    alert(`Attack experiment failed: ${err.message}`);
    if (el.playbackStatusMsg) el.playbackStatusMsg.textContent = `Error: ${err.message}`;
  } finally {
    isMutatingState = false;
    setControlsDisabled(false);
  }
}

function displayExperimentResult(res) {
  lastExperimentResult = res;

  if (el.resExpectedLabel) el.resExpectedLabel.textContent = res.expected_label;
  if (el.resPredictedClass) {
    el.resPredictedClass.innerHTML = `<span class="badge ${getBadgeClass(res.defender_prediction)}">${res.defender_prediction}</span>`;
  }

  if (el.resOutcomePill) {
    el.resOutcomePill.className = `outcome-pill ${getOutcomeClass(res.outcome)}`;
    el.resOutcomePill.textContent = res.outcome.replace('_', ' ');
  }
  if (el.resOutcomeText) {
    el.resOutcomeText.textContent = res.outcome.replace('_', ' ');
    el.resOutcomeText.style.color = res.outcome.includes('POSITIVE') ? '#34d399' : (res.outcome.includes('NEGATIVE') && res.outcome.includes('TRUE') ? '#22d3ee' : '#f87171');
  }

  if (el.resRiskScore) el.resRiskScore.textContent = res.detection_score.toFixed(3);
  if (el.resLatencyMs) el.resLatencyMs.textContent = `${res.detection_latency_ms.toFixed(1)} ms`;
  if (el.resModifiedCount) el.resModifiedCount.textContent = (res.modified_fields || []).length;

  if (el.resContributingLayers) {
    el.resContributingLayers.textContent = (res.contributing_layers || []).join(' &bull; ') || 'Baseline Normal';
  }
}

function resetCurrentExperiment() {
  lastExperimentResult = null;
  if (el.resExpectedLabel) el.resExpectedLabel.textContent = 'NORMAL';
  if (el.resPredictedClass) el.resPredictedClass.textContent = 'NORMAL';
  if (el.resOutcomePill) {
    el.resOutcomePill.className = 'outcome-pill outcome-tn';
    el.resOutcomePill.textContent = 'AWAITING EVALUATION';
  }
  if (el.resOutcomeText) el.resOutcomeText.textContent = 'AWAITING RUN';
  if (el.resRiskScore) el.resRiskScore.textContent = '0.000';
  if (el.resLatencyMs) el.resLatencyMs.textContent = '-- ms';
  if (el.resModifiedCount) el.resModifiedCount.textContent = '0';
  if (el.resContributingLayers) el.resContributingLayers.textContent = 'Ready to evaluate.';
  renderWindowChart(currentWindowObservations);
}

// Detection Evidence Rendering (Area 2)
function renderEvidence(analysis, expResult) {
  if (!analysis) return;

  if (expResult && el.evidenceExpId) el.evidenceExpId.textContent = expResult.experiment_id;
  if (expResult && el.evidenceTimestamp) el.evidenceTimestamp.textContent = formatTimestamp(expResult.timestamp);

  const dec = analysis.decision || {};
  const ml = analysis.ml || {};
  const sem = analysis.semantic || {};
  const temp = analysis.temporal || {};
  const struct = analysis.structural || {};

  // Joint Decision Hero Banner
  if (el.jointClassification) {
    el.jointClassification.innerHTML = `<span class="badge ${getBadgeClass(dec.classification)}">${dec.classification || 'NORMAL'}</span>`;
  }
  if (el.jointRisk) el.jointRisk.textContent = `Risk: ${formatNullableNumber(dec.risk_score, 3, '', '0.000')}`;
  if (el.jointIntegrity) el.jointIntegrity.textContent = `Integrity: ${formatNullableNumber(dec.integrity_score, 1, '%', '100.0%')}`;
  if (el.jointExplanation) el.jointExplanation.textContent = dec.explanation || 'Operational records and sensor telemetry are internally consistent.';

  if (el.jointDecisionBanner) {
    const cls = dec.classification || 'NORMAL';
    if (cls.includes('ATTACK')) {
      el.jointDecisionBanner.className = 'decision-banner violation';
    } else if (cls === 'SUSPICIOUS' || cls === 'LOW') {
      el.jointDecisionBanner.className = 'decision-banner warning';
    } else {
      el.jointDecisionBanner.className = 'decision-banner';
    }
  }

  // 1. ML Detector
  if (el.mlStatus) el.mlStatus.innerHTML = `<span class="badge ${getBadgeClass(ml.status)}">${ml.status || 'NORMAL'}</span>`;
  if (el.mlScore) el.mlScore.textContent = formatNullableNumber(ml.anomaly_score, 3, '', '0.000');
  if (el.mlFlag) el.mlFlag.textContent = ml.is_anomaly ? 'TRUE (Anomaly Outlier)' : 'FALSE (Normal)';
  if (el.mlMode) el.mlMode.textContent = (ml.details && ml.details.mode) || 'environmental_multisensor';
  if (el.mlFeatures) el.mlFeatures.textContent = (ml.features_evaluated || []).join(', ') || 'Standard feature set';

  // 2. Temporal Analysis
  if (el.tempStatus) el.tempStatus.innerHTML = `<span class="badge ${getBadgeClass(temp.status)}">${temp.status || 'STABLE'}</span>`;
  if (el.tempScore) el.tempScore.textContent = formatNullableNumber(temp.temporal_score, 2, '', '0.00');
  if (el.tempPersistence) el.tempPersistence.textContent = `${temp.persistence ?? 0} consecutive steps`;
  if (el.tempRecurrence) el.tempRecurrence.textContent = `${temp.recurrence ?? 0} / ${temp.window_size || 10} window`;

  // 3. Semantic Constraints C1-C4
  if (el.semStatus) el.semStatus.innerHTML = `<span class="badge ${getBadgeClass(sem.status)}">${sem.status || 'NORMAL'}</span>`;
  if (el.semScore) el.semScore.textContent = formatNullableNumber(sem.semantic_score, 2, '', '0.00');

  const constraints = sem.constraints || [];
  const c1 = constraints.find(c => c.constraint === 'C1');
  const c2 = constraints.find(c => c.constraint === 'C2');
  const c3 = constraints.find(c => c.constraint === 'C3');
  const c4 = constraints.find(c => c.constraint === 'C4');

  if (c1 && el.c1Block) {
    const isNA = c1.status === 'NOT_APPLICABLE';
    el.c1Block.innerHTML = `
      <div class="constraint-header">
        <span>C1: Capacity Consistency</span>
        <span class="badge ${getBadgeClass(c1.status)}">${c1.status}</span>
      </div>
      ${isNA
        ? `<div style="color: var(--text-muted); font-size: 0.8rem;">Inventory ledger fields not present in environmental dataset.</div>`
        : `<div><strong>Expected:</strong> &le; ${formatNullableNumber(c1.expected, 1, 't')} | <strong>Actual:</strong> ${formatNullableNumber(c1.actual, 1, 't')}</div>`}
      <div style="color: var(--text-secondary); font-size: 0.75rem; margin-top: 0.25rem;">${c1.message}</div>
    `;
  }

  if (c2 && el.c2Block) {
    const isNA = c2.status === 'NOT_APPLICABLE';
    el.c2Block.innerHTML = `
      <div class="constraint-header">
        <span>C2: Inventory Flow</span>
        <span class="badge ${getBadgeClass(c2.status)}">${c2.status}</span>
      </div>
      ${isNA
        ? `<div style="color: var(--text-muted); font-size: 0.8rem;">Shipment transfer ledgers not present in environmental dataset.</div>`
        : `<div><strong>Expected:</strong> ${formatNullableNumber(c2.expected, 1, 't')} | <strong>Actual:</strong> ${formatNullableNumber(c2.actual, 1, 't')}</div>`}
      <div style="color: var(--text-secondary); font-size: 0.75rem; margin-top: 0.25rem;">${c2.message}</div>
    `;
  }

  if (c3 && el.c3Block) {
    const actTemp = c3.actual && c3.actual.temperature != null ? formatNullableNumber(c3.actual.temperature, 1, '°C') : '--';
    const actHum = c3.actual && c3.actual.humidity != null ? formatNullableNumber(c3.actual.humidity, 1, '%') : '--';
    el.c3Block.innerHTML = `
      <div class="constraint-header">
        <span>C3: Historical Envelope</span>
        <span class="badge ${getBadgeClass(c3.status)}">${c3.status}</span>
      </div>
      <div><strong>Actual:</strong> Temp=${actTemp}, Hum=${actHum}</div>
      <div style="color: var(--text-secondary); font-size: 0.75rem; margin-top: 0.25rem;">${c3.message}</div>
    `;
  }

  if (c4 && el.c4Block) {
    const isNA = c4.status === 'NOT_APPLICABLE';
    el.c4Block.innerHTML = `
      <div class="constraint-header">
        <span>C4: Spatial Sensor Consistency</span>
        <span class="badge ${getBadgeClass(c4.status)}">${c4.status}</span>
      </div>
      ${isNA
        ? `<div style="color: var(--text-muted); font-size: 0.8rem;">Multi-sensor spatial array not present in current mode.</div>`
        : `<div><strong>Inter-Sensor Delta:</strong> ${formatNullableNumber(c4.actual, 1, '°C')} (Max Allowed: ${formatNullableNumber(c4.expected, 1, '°C')})</div>`}
      <div style="color: var(--text-secondary); font-size: 0.75rem; margin-top: 0.25rem;">${c4.message}</div>
    `;
  }

  // 4. Structural Engine
  if (el.structStatus) el.structStatus.innerHTML = `<span class="badge ${getBadgeClass(struct.status)}">${struct.status || 'ISOLATED'}</span>`;
  if (el.structScore) el.structScore.textContent = formatNullableNumber(struct.structural_score, 2, '', '0.00');
  if (el.structNodes) {
    el.structNodes.textContent = (struct.affected_nodes || []).length > 0 ? struct.affected_nodes.join(', ') : 'None (Isolated)';
  }
  if (el.structEdges) {
    el.structEdges.textContent = (struct.correlated_edges || []).length > 0 ? struct.correlated_edges.map(e => e.join(' ↔ ')).join('; ') : 'None';
  }

  // 5. Audit Chain verification
  fetchJson(`${API_BASE}/security/audit-chain/verify`).then(audit => {
    if (el.auditValidStatus) {
      el.auditValidStatus.textContent = audit.valid ? 'VERIFIED INTACT (SHA-256)' : 'TAMPER DETECTED';
      el.auditValidStatus.style.color = audit.valid ? '#10b981' : '#ef4444';
    }
    if (el.auditEventsCount) el.auditEventsCount.textContent = `${audit.total_events || 0} Cryptographically Linked Events`;
    if (el.auditLatestHash) el.auditLatestHash.textContent = audit.latest_event_hash || 'None';
  }).catch(() => null);

  // Raw JSON
  if (el.rawEvidenceJson) {
    el.rawEvidenceJson.textContent = JSON.stringify(analysis, null, 2);
  }
}

function toggleRawEvidence() {
  if (!el.expandableRawBody || !el.rawEvidenceToggleIcon) return;
  const isHidden = el.expandableRawBody.style.display === 'none';
  el.expandableRawBody.style.display = isHidden ? 'block' : 'none';
  el.rawEvidenceToggleIcon.innerHTML = isHidden ? '&minus; Collapse' : '&plus; Expand';
}

// Experiment History & Evaluation (Area 3)
async function loadExperimentHistory() {
  try {
    const scFilter = el.filterScenario ? el.filterScenario.value : 'ALL';
    const sensorFilter = el.filterSensor ? el.filterSensor.value : 'ALL';
    const outcomeFilter = el.filterOutcome ? el.filterOutcome.value : 'ALL';

    const params = new URLSearchParams();
    if (scFilter !== 'ALL') params.append('attack_type', scFilter);
    if (sensorFilter !== 'ALL') params.append('target_sensor', sensorFilter);
    if (outcomeFilter !== 'ALL') params.append('outcome', outcomeFilter);

    const [history, metrics] = await Promise.all([
      fetchJson(`${API_BASE}/experiments/history?${params.toString()}`),
      fetchJson(`${API_BASE}/experiments/metrics`),
    ]);

    // Update Benchmark Metrics Strip
    if (el.metricTotalRuns) el.metricTotalRuns.textContent = metrics.total_experiments;
    if (el.metricTp) el.metricTp.textContent = metrics.true_positives;
    if (el.metricTn) el.metricTn.textContent = metrics.true_negatives;
    if (el.metricFp) el.metricFp.textContent = metrics.false_positives;
    if (el.metricFn) el.metricFn.textContent = metrics.false_negatives;

    if (el.metricPrecision) el.metricPrecision.textContent = metrics.precision != null ? `${(metrics.precision * 100).toFixed(1)}%` : 'N/A';
    if (el.metricRecall) el.metricRecall.textContent = metrics.recall != null ? `${(metrics.recall * 100).toFixed(1)}%` : 'N/A';
    if (el.metricF1) el.metricF1.textContent = metrics.f1_score != null ? metrics.f1_score.toFixed(3) : 'N/A';
    if (el.metricFpr) el.metricFpr.textContent = metrics.false_positive_rate != null ? `${(metrics.false_positive_rate * 100).toFixed(2)}%` : 'N/A';
    if (el.metricAvgLatency) el.metricAvgLatency.textContent = `${metrics.avg_latency_ms.toFixed(1)} ms`;

    // Render Table Rows
    if (!el.historyTbody) return;
    if (history.length === 0) {
      el.historyTbody.innerHTML = `<tr><td colspan="10" class="empty-state">No matching experiments recorded.</td></tr>`;
      return;
    }

    el.historyTbody.innerHTML = history.map(exp => `
      <tr>
        <td style="font-family: var(--font-mono); font-weight: 700; text-align: left;">${exp.experiment_id}</td>
        <td style="font-family: var(--font-mono); font-size: 0.75rem;">Step ${exp.step}<br><span style="color:var(--text-muted);">${formatTimestamp(exp.timestamp)}</span></td>
        <td><span class="badge ${exp.is_attack ? 'badge-potential_attack' : 'badge-normal'}">${exp.attack_type}</span></td>
        <td style="font-family: var(--font-mono);">${exp.target_sensor || 'None'}</td>
        <td><span class="badge badge-ground-truth">${exp.expected_label}</span></td>
        <td><span class="badge ${getBadgeClass(exp.defender_prediction)}">${exp.defender_prediction}</span></td>
        <td><span class="outcome-pill ${getOutcomeClass(exp.outcome)}">${exp.outcome.replace('_', ' ')}</span></td>
        <td style="font-family: var(--font-mono); font-weight: 600;">${exp.detection_score.toFixed(3)}</td>
        <td style="font-family: var(--font-mono); font-size: 0.75rem;">${exp.detection_latency_ms.toFixed(1)} ms</td>
        <td>
          <button class="btn" style="padding: 0.2rem 0.5rem; font-size: 0.75rem;" onclick="inspectExperiment('${exp.experiment_id}')">
            Evidence
          </button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Failed to load history:', err);
  }
}

async function inspectExperiment(experimentId) {
  try {
    const exp = await fetchJson(`${API_BASE}/experiments/${experimentId}`);
    displayExperimentResult(exp);
    renderEvidence(exp.security_analysis, exp);
    switchTab('evidence');
  } catch (err) {
    alert(`Could not load experiment details: ${err.message}`);
  }
}

function exportHistoryCSV() {
  window.open(`${API_BASE}/experiments/history/export`, '_blank');
}

async function clearExperimentHistory() {
  if (!confirm('Clear all recorded experiment evaluation logs?')) return;
  try {
    await fetchJson(`${API_BASE}/experiments/reset`, { method: 'POST' });
    resetCurrentExperiment();
    await loadExperimentHistory();
  } catch (err) {
    alert(`Reset failed: ${err.message}`);
  }
}

function setControlsDisabled(disabled) {
  if (el.btnRunBaseline) el.btnRunBaseline.disabled = disabled;
  if (el.btnRunAttack) el.btnRunAttack.disabled = disabled;
  if (el.btnResetExp) el.btnResetExp.disabled = disabled;
  if (el.btnStep) el.btnStep.disabled = disabled;
  if (el.btnSeek) el.btnSeek.disabled = disabled;
  if (el.btnReset) el.btnReset.disabled = disabled;
  if (el.btnToggleMode) el.btnToggleMode.disabled = disabled;
}

// Global Refresh
async function refreshAll() {
  await Promise.all([
    refreshDatasetState(),
    refreshSecurityAnalysis(),
  ]);
  if (activeTab === 'history') {
    await loadExperimentHistory();
  }
}

async function refreshSecurityAnalysis() {
  try {
    const analysis = await fetchJson(`${API_BASE}/security/latest`);
    renderEvidence(analysis, lastExperimentResult);
  } catch (err) {
    console.warn('Could not load latest security analysis:', err);
  }
}

// Initialization
document.addEventListener('DOMContentLoaded', () => {
  onScenarioChanged();
  refreshAll();
  loadExperimentHistory();

  // Support direct URL tab navigation and auto-run parameter for automated verification
  const urlParams = new URLSearchParams(window.location.search);
  const initialTab = urlParams.get('tab');
  if (initialTab && ['dashboard', 'evidence', 'history'].includes(initialTab)) {
    switchTab(initialTab);
  }

  const autoRun = urlParams.get('auto_run');
  if (autoRun === 'baseline') {
    setTimeout(() => executeBaseline(), 600);
  } else if (autoRun === 'attack') {
    setTimeout(() => executeAttackExperiment(), 600);
  }

  // Background polling for clock & dataset
  pollTimer = setInterval(() => {
    if (!isMutatingState && activeTab === 'dashboard') {
      refreshDatasetState();
    }
  }, POLL_INTERVAL_MS);
});

// Backward compatibility functions for test suite and legacy bindings
function refreshDashboard() {
  return refreshAll();
}

function advanceSimulation() {
  return stepDatasetObservation();
}

function seekPlayback(step) {
  return seekDatasetPlayback(step);
}

function toggleDataSourceMode() {
  return togglePlaybackMode();
}

function triggerScenario(scenarioId) {
  if (el.attackScenarioSelect) el.attackScenarioSelect.value = scenarioId;
  onScenarioChanged();
  return executeAttackExperiment();
}
