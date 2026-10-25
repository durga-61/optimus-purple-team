/**
 * Optimus — Attack Simulator Portal Controller
 * Portal 3: Controlled attack injection, ground-truth tracking,
 * and empirical benchmark evaluation outside the Defender pipeline.
 */

let currentStep = 0;
let currentObservation = null;
let lastExperimentResult = null;
let isExecuting = false;

// Scenario specifications and default parameters
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
    desc: 'Injects a localized thermal gradient into one sensor relative to the remaining spatial array, triggering C4 spatial delta alerts.',
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

// 1. Fetch Target Observation State
async function refreshSimulatorState() {
  try {
    const obs = await fetchJson(`${API_BASE}/warehouse/current`);
    currentObservation = obs;
    currentStep = obs.step || 0;

    const stepInput = document.getElementById('sim-step-input');
    if (stepInput && document.activeElement !== stepInput) {
      stepInput.value = currentStep;
    }

    const timeEl = document.getElementById('sim-obs-timestamp');
    if (timeEl) timeEl.textContent = formatTimestamp(obs.timestamp);

    const stepBadge = document.getElementById('sim-step-badge');
    if (stepBadge) stepBadge.textContent = `Step ${currentStep} / 156,835`;

    updateDiffPreview();
  } catch (err) {
    console.warn('Failed to refresh simulator target observation:', err);
  }
}

// 2. Scenario Dropdown Change Handler
function onScenarioChanged() {
  const scSelect = document.getElementById('attack-scenario-select');
  if (!scSelect) return;
  const sc = scSelect.value;
  const cfg = SCENARIO_DEFAULTS[sc] || SCENARIO_DEFAULTS['temperature_manipulation'];

  const descEl = document.getElementById('attack-scenario-desc');
  if (descEl) descEl.textContent = cfg.desc;

  const grpMag = document.getElementById('group-magnitude');
  const grpDrift = document.getElementById('group-drift-steps');
  const grpReplay = document.getElementById('group-replay-step');
  const lblMag = document.getElementById('label-magnitude');
  const inpMag = document.getElementById('attack-magnitude-input');

  if (grpMag) {
    grpMag.style.display = cfg.paramGroup === 'group-magnitude' ? 'flex' : 'none';
    if (lblMag && cfg.label) lblMag.textContent = cfg.label;
    if (inpMag && cfg.defaultVal !== null) inpMag.value = cfg.defaultVal;
  }
  if (grpDrift) {
    grpDrift.style.display = cfg.paramGroup === 'group-drift-steps' ? 'flex' : 'none';
  }
  if (grpReplay) {
    grpReplay.style.display = cfg.paramGroup === 'group-replay-step' ? 'flex' : 'none';
  }

  updateDiffPreview();
}

// 3. Update Modification Diff Table
function updateDiffPreview() {
  const tbody = document.getElementById('attack-diff-tbody');
  if (!tbody) return;

  const scSelect = document.getElementById('attack-scenario-select');
  const sensorSelect = document.getElementById('attack-target-sensor-select');
  const magInput = document.getElementById('attack-magnitude-input');
  const driftInput = document.getElementById('attack-drift-steps-input');
  const replayInput = document.getElementById('attack-replay-step-input');

  const sc = scSelect ? scSelect.value : 'temperature_manipulation';
  const targetSensor = sensorSelect ? sensorSelect.value : 'SENSOR01';

  const sData = (currentObservation && currentObservation.sensors && currentObservation.sensors[targetSensor]) || {
    temperature: 21.2,
    humidity: 62.5,
  };

  const origTemp = sData.temperature != null ? sData.temperature : 21.2;
  const origHum = sData.humidity != null ? sData.humidity : 62.5;

  let propName = 'Temperature';
  let origValStr = `${origTemp.toFixed(1)} °C`;
  let modValStr = '--';
  let deltaStr = '--';

  if (sc === 'temperature_manipulation') {
    const mag = parseFloat(magInput ? magInput.value : 12.0) || 12.0;
    const modTemp = origTemp + mag;
    modValStr = `${modTemp.toFixed(1)} °C`;
    deltaStr = `${mag >= 0 ? '+' : ''}${mag.toFixed(1)} °C`;
  } else if (sc === 'humidity_manipulation') {
    propName = 'Humidity';
    origValStr = `${origHum.toFixed(1)} %`;
    const mag = parseFloat(magInput ? magInput.value : 25.0) || 25.0;
    const modHum = Math.min(100, Math.max(0, origHum + mag));
    modValStr = `${modHum.toFixed(1)} %`;
    deltaStr = `${mag >= 0 ? '+' : ''}${mag.toFixed(1)} %`;
  } else if (sc === 'sensor_drift') {
    const steps = parseInt(driftInput ? driftInput.value : 5, 10) || 5;
    const rate = 0.8;
    const totalDrift = rate * steps;
    const modTemp = origTemp + totalDrift;
    modValStr = `${modTemp.toFixed(1)} °C`;
    deltaStr = `+${totalDrift.toFixed(1)} °C (${steps} steps × 0.8°)`;
  } else if (sc === 'replay_substitution') {
    const rStep = parseInt(replayInput ? replayInput.value : 0, 10) || 0;
    modValStr = `Replayed from Step ${rStep}`;
    deltaStr = `Telemetry Frozen / Replaced`;
  } else if (sc === 'cross_sensor_inconsistency') {
    const mag = parseFloat(magInput ? magInput.value : 8.0) || 8.0;
    const modTemp = origTemp + mag;
    modValStr = `${modTemp.toFixed(1)} °C`;
    deltaStr = `+${mag.toFixed(1)} °C (Spatial Gradient Violation)`;
  } else if (sc === 'sensor_dropout') {
    propName = 'All Telemetry';
    origValStr = 'Online DHT22 Readings';
    modValStr = 'Suppressed (Dropout)';
    deltaStr = 'Channel Drop / Null Values';
  }

  tbody.innerHTML = `
    <tr>
      <td style="font-weight: 700; color: #fff;">${targetSensor}</td>
      <td style="color: var(--text-secondary);">${propName}</td>
      <td class="diff-orig">${origValStr}</td>
      <td class="diff-mod">${modValStr}</td>
      <td style="color: #38bdf8; font-weight: 600;">${deltaStr}</td>
    </tr>
  `;
}

// 4. Seek to Step in Simulator
async function simJumpToStep() {
  const input = document.getElementById('sim-step-input');
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
    currentObservation = res.observation;
    await refreshSimulatorState();
  } catch (err) {
    alert(`Seek failed: ${err.message}`);
  }
}

// 5. Run Baseline (Normal Evaluation)
async function executeBaseline() {
  if (isExecuting) return;
  isExecuting = true;
  setSimControlsDisabled(true);

  const statusMsg = document.getElementById('playback-status-msg');
  if (statusMsg) statusMsg.textContent = 'Submitting authentic baseline observation to Defender pipeline...';

  try {
    const res = await fetchJson(`${API_BASE}/experiments/baseline`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ step: currentStep }),
    });

    displayExperimentResult(res);
    await loadExperimentHistory();

    if (statusMsg) {
      statusMsg.textContent = `Baseline evaluated (${res.experiment_id}). Ground Truth: NORMAL, Defender: ${res.defender_prediction}, Outcome: ${res.outcome}.`;
    }
  } catch (err) {
    alert(`Baseline evaluation failed: ${err.message}`);
    if (statusMsg) statusMsg.textContent = `Error: ${err.message}`;
  } finally {
    isExecuting = false;
    setSimControlsDisabled(false);
  }
}

// 6. Run Attack Experiment
async function executeAttackExperiment() {
  if (isExecuting) return;
  isExecuting = true;
  setSimControlsDisabled(true);

  const statusMsg = document.getElementById('playback-status-msg');
  if (statusMsg) statusMsg.textContent = 'Injecting attack mutation and submitting to Defender pipeline...';

  try {
    const sc = document.getElementById('attack-scenario-select').value;
    const target = document.getElementById('attack-target-sensor-select').value;
    const magInput = document.getElementById('attack-magnitude-input');
    const driftInput = document.getElementById('attack-drift-steps-input');
    const replayInput = document.getElementById('attack-replay-step-input');

    const mag = magInput ? parseFloat(magInput.value) : null;
    const driftSteps = driftInput ? parseInt(driftInput.value, 10) : 5;
    const replayStep = replayInput ? parseInt(replayInput.value, 10) : 0;

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
    await loadExperimentHistory();

    if (statusMsg) {
      statusMsg.textContent = `Attack experiment completed (${res.experiment_id}). Ground Truth: ATTACK, Defender: ${res.defender_prediction}, Outcome: ${res.outcome}.`;
    }
  } catch (err) {
    alert(`Attack experiment failed: ${err.message}`);
    if (statusMsg) statusMsg.textContent = `Error: ${err.message}`;
  } finally {
    isExecuting = false;
    setSimControlsDisabled(false);
  }
}

// 7. Display Results Summary Card
function displayExperimentResult(res) {
  lastExperimentResult = res;

  const expLabel = document.getElementById('res-expected-label');
  const predClass = document.getElementById('res-predicted-class');
  const pill = document.getElementById('res-outcome-pill');
  const risk = document.getElementById('res-risk-score');
  const lat = document.getElementById('res-latency-ms');
  const modCnt = document.getElementById('res-modified-count');
  const layers = document.getElementById('res-contributing-layers');
  const expId = document.getElementById('res-exp-id');

  if (expId) expId.textContent = res.experiment_id;
  if (expLabel) expLabel.textContent = res.expected_label;
  if (predClass) {
    predClass.innerHTML = `<span class="badge ${getBadgeClass(res.defender_prediction)}">${res.defender_prediction}</span>`;
  }
  if (pill) {
    pill.className = `outcome-pill ${getOutcomeClass(res.outcome)}`;
    pill.textContent = res.outcome.replace('_', ' ');
  }
  if (risk) risk.textContent = res.detection_score.toFixed(3);
  if (lat) lat.textContent = `${res.detection_latency_ms.toFixed(1)} ms`;
  if (modCnt) modCnt.textContent = (res.modified_fields || []).length;
  if (layers) {
    layers.textContent = (res.contributing_layers || []).join(' • ') || 'Baseline Normal';
  }
}

// 8. Reset Current Experiment Form
function resetCurrentExperiment() {
  lastExperimentResult = null;
  const pill = document.getElementById('res-outcome-pill');
  const expLabel = document.getElementById('res-expected-label');
  const predClass = document.getElementById('res-predicted-class');
  const risk = document.getElementById('res-risk-score');
  const lat = document.getElementById('res-latency-ms');
  const modCnt = document.getElementById('res-modified-count');
  const layers = document.getElementById('res-contributing-layers');
  const expId = document.getElementById('res-exp-id');
  const statusMsg = document.getElementById('playback-status-msg');

  if (expId) expId.textContent = 'None';
  if (expLabel) expLabel.textContent = 'NORMAL';
  if (predClass) predClass.innerHTML = '<span class="badge badge-normal">NORMAL</span>';
  if (pill) {
    pill.className = 'outcome-pill outcome-tn';
    pill.textContent = 'AWAITING EVALUATION';
  }
  if (risk) risk.textContent = '0.000';
  if (lat) lat.textContent = '-- ms';
  if (modCnt) modCnt.textContent = '0';
  if (layers) layers.textContent = 'Ready to evaluate.';
  if (statusMsg) statusMsg.textContent = 'Ready to inject controlled attack experiments.';

  updateDiffPreview();
}

// 9. Load Experiment History & Metrics Strip
async function loadExperimentHistory() {
  try {
    const scFilter = document.getElementById('filter-scenario');
    const sensorFilter = document.getElementById('filter-sensor');
    const outcomeFilter = document.getElementById('filter-outcome');

    const params = new URLSearchParams();
    if (scFilter && scFilter.value !== 'ALL') params.append('attack_type', scFilter.value);
    if (sensorFilter && sensorFilter.value !== 'ALL') params.append('target_sensor', sensorFilter.value);
    if (outcomeFilter && outcomeFilter.value !== 'ALL') params.append('outcome', outcomeFilter.value);

    const [history, metrics] = await Promise.all([
      fetchJson(`${API_BASE}/experiments/history?${params.toString()}`),
      fetchJson(`${API_BASE}/experiments/metrics`),
    ]);

    // Benchmark Metrics Strip
    const mTotal = document.getElementById('metric-total-runs');
    const mTp = document.getElementById('metric-tp');
    const mTn = document.getElementById('metric-tn');
    const mFp = document.getElementById('metric-fp');
    const mFn = document.getElementById('metric-fn');
    const mPrec = document.getElementById('metric-precision');
    const mRec = document.getElementById('metric-recall');
    const mF1 = document.getElementById('metric-f1');
    const mFpr = document.getElementById('metric-fpr');
    const mLat = document.getElementById('metric-avg-latency');

    if (mTotal) mTotal.textContent = metrics.total_experiments;
    if (mTp) mTp.textContent = metrics.true_positives;
    if (mTn) mTn.textContent = metrics.true_negatives;
    if (mFp) mFp.textContent = metrics.false_positives;
    if (mFn) mFn.textContent = metrics.false_negatives;

    if (mPrec) mPrec.textContent = metrics.precision != null ? `${(metrics.precision * 100).toFixed(1)}%` : 'N/A';
    if (mRec) mRec.textContent = metrics.recall != null ? `${(metrics.recall * 100).toFixed(1)}%` : 'N/A';
    if (mF1) mF1.textContent = metrics.f1_score != null ? metrics.f1_score.toFixed(3) : 'N/A';
    if (mFpr) mFpr.textContent = metrics.false_positive_rate != null ? `${(metrics.false_positive_rate * 100).toFixed(2)}%` : 'N/A';
    if (mLat) mLat.textContent = `${metrics.avg_latency_ms.toFixed(1)} ms`;

    // History Table Rows
    const tbody = document.getElementById('history-tbody');
    if (!tbody) return;

    if (history.length === 0) {
      tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">No evaluation logs recorded yet. Run a baseline or attack experiment to record entries.</td></tr>`;
      return;
    }

    tbody.innerHTML = history.map(exp => `
      <tr>
        <td style="font-family: var(--font-mono); font-weight: 700; text-align: left; color: #38bdf8;">${exp.experiment_id}</td>
        <td style="font-family: var(--font-mono); font-size: 0.75rem;">Step ${exp.step}<br><span style="color:var(--text-muted);">${formatTimestamp(exp.timestamp)}</span></td>
        <td><span class="badge ${exp.is_attack ? 'badge-potential_attack' : 'badge-normal'}">${exp.attack_type}</span></td>
        <td style="font-family: var(--font-mono);">${exp.target_sensor || 'None'}</td>
        <td><span class="badge badge-ground-truth">${exp.expected_label}</span></td>
        <td><span class="badge ${getBadgeClass(exp.defender_prediction)}">${exp.defender_prediction}</span></td>
        <td><span class="outcome-pill ${getOutcomeClass(exp.outcome)}">${exp.outcome.replace('_', ' ')}</span></td>
        <td style="font-family: var(--font-mono); font-weight: 600;">${exp.detection_score.toFixed(3)}</td>
        <td style="font-family: var(--font-mono); font-size: 0.75rem;">${exp.detection_latency_ms.toFixed(1)} ms</td>
        <td>
          <button class="btn" style="padding: 0.2rem 0.5rem; font-size: 0.75rem;" onclick="viewExperimentEvidence('${exp.experiment_id}')">
            View
          </button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Failed to load experiment history:', err);
  }
}

// 10. Actions: Export CSV & Clear History
function exportHistoryCSV() {
  window.open(`${API_BASE}/experiments/history/export`, '_blank');
}

async function clearExperimentHistory() {
  if (!confirm('Clear all recorded evaluation experiments from in-memory history?')) return;
  try {
    await fetchJson(`${API_BASE}/experiments/reset`, { method: 'POST' });
    resetCurrentExperiment();
    await loadExperimentHistory();
  } catch (err) {
    alert(`Reset failed: ${err.message}`);
  }
}

// 11. View Experiment Evidence in Defender
async function viewExperimentEvidence(experimentId) {
  try {
    const exp = await fetchJson(`${API_BASE}/experiments/${experimentId}`);
    displayExperimentResult(exp);

    // Open detail modal with raw evidence JSON
    const modal = document.getElementById('evidence-detail-modal');
    const pre = document.getElementById('modal-evidence-pre');
    if (modal && pre) {
      pre.textContent = JSON.stringify(exp, null, 2);
      modal.style.display = 'flex';
    }
  } catch (err) {
    alert(`Could not load experiment details: ${err.message}`);
  }
}

function closeEvidenceModal() {
  const modal = document.getElementById('evidence-detail-modal');
  if (modal) modal.style.display = 'none';
}

// 12. Python Reproducibility Snippet Modal
function showReproducibilityModal() {
  const modal = document.getElementById('reproducibility-modal');
  const codeEl = document.getElementById('reproducibility-code');
  if (!modal || !codeEl) return;

  const sc = document.getElementById('attack-scenario-select').value;
  const target = document.getElementById('attack-target-sensor-select').value;
  const magInput = document.getElementById('attack-magnitude-input');
  const mag = magInput ? parseFloat(magInput.value) : 12.0;

  const pythonScript = `"""
Optimus Cold-Storage Security Monitor — Attack Experiment Reproducibility Script
Replicates the controlled data-integrity attack experiment against Defender API.
"""
import requests
import json

BASE_URL = "http://127.0.0.1:8000"

def run_experiment():
    # 1. Target Step: ${currentStep}
    # 2. Attack Configuration
    payload = {
        "step": ${currentStep},
        "configuration": {
            "scenario": "${sc}",
            "target_sensor": "${target}",
            "magnitude": ${mag},
            "drift_rate": 0.8,
            "drift_steps": 5,
            "replay_step": 0,
            "seed": 42
        }
    }

    # 3. Submit to Attack Experiment Endpoint
    response = requests.post(f"{BASE_URL}/api/experiments/attack", json=payload)
    response.raise_for_status()
    result = response.json()

    print("Experiment ID:       ", result["experiment_id"])
    print("Ground Truth:        ", result["expected_label"])
    print("Defender Prediction: ", result["defender_prediction"])
    print("Evaluation Outcome:  ", result["outcome"])
    print("Detection Score:     ", result["detection_score"])
    print("Latency:             ", f"{result['detection_latency_ms']:.2f} ms")
    print("Contributing Layers: ", result["contributing_layers"])

if __name__ == "__main__":
    run_experiment()
`;

  codeEl.textContent = pythonScript;
  modal.style.display = 'flex';
}

function closeReproducibilityModal() {
  const modal = document.getElementById('reproducibility-modal');
  if (modal) modal.style.display = 'none';
}

function copyReproducibilityCode() {
  const codeEl = document.getElementById('reproducibility-code');
  if (!codeEl) return;
  navigator.clipboard.writeText(codeEl.textContent).then(() => {
    alert('Reproducibility Python script copied to clipboard!');
  }).catch(() => {
    alert('Failed to copy to clipboard.');
  });
}

function setSimControlsDisabled(disabled) {
  const b1 = document.getElementById('btn-run-baseline');
  const b2 = document.getElementById('btn-run-attack');
  const b3 = document.getElementById('btn-reset-exp');
  if (b1) b1.disabled = disabled;
  if (b2) b2.disabled = disabled;
  if (b3) b3.disabled = disabled;
}

// Initialization
document.addEventListener('DOMContentLoaded', () => {
  onScenarioChanged();
  refreshSimulatorState();
  loadExperimentHistory();

  // Listen to input changes for live diff updates
  const magInput = document.getElementById('attack-magnitude-input');
  if (magInput) magInput.addEventListener('input', updateDiffPreview);

  const driftInput = document.getElementById('attack-drift-steps-input');
  if (driftInput) driftInput.addEventListener('input', updateDiffPreview);

  const replayInput = document.getElementById('attack-replay-step-input');
  if (replayInput) replayInput.addEventListener('input', updateDiffPreview);
});
