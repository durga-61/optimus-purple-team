/**
 * Optimus — Defender Portal Controller
 * Responsible strictly for incoming telemetry ingestion, multi-layer detection,
 * explainable evidentiary breakdown, and SHA-256 audit-chain verification.
 * Zero attack controls. Zero ground-truth leakage.
 */

let pollTimer = null;
let isRefreshing = false;

async function refreshDefenderState() {
  if (isRefreshing) return;
  isRefreshing = true;

  try {
    const [analysis, currentObs, audit] = await Promise.all([
      fetchJson(`${API_BASE}/security/latest`),
      fetchJson(`${API_BASE}/warehouse/current`).catch(() => null),
      fetchJson(`${API_BASE}/security/audit-chain/verify`).catch(() => null),
    ]);

    renderIncomingTelemetry(currentObs);
    renderSecurityDecision(analysis);
    renderDetectionLayers(analysis);
    if (audit) renderAuditChain(audit);

    // Raw JSON Payload
    const rawEl = document.getElementById('raw-evidence-json');
    if (rawEl) {
      rawEl.textContent = JSON.stringify(analysis, null, 2);
    }

    const connBanner = document.getElementById('connection-banner');
    if (connBanner) connBanner.classList.add('hidden');
    const healthDot = document.getElementById('health-dot');
    if (healthDot) healthDot.className = 'status-dot';
  } catch (err) {
    console.error('Defender refresh failed:', err);
    const connBanner = document.getElementById('connection-banner');
    if (connBanner) connBanner.classList.remove('hidden');
    const healthDot = document.getElementById('health-dot');
    if (healthDot) healthDot.className = 'status-dot offline';
  } finally {
    isRefreshing = false;
  }
}

// 1. Render incoming observation and sensor array
function renderIncomingTelemetry(obs) {
  if (!obs) return;

  const obsIdEl = document.getElementById('def-observation-id');
  if (obsIdEl) obsIdEl.textContent = `OBS-${String(obs.step || 0).padStart(6, '0')}`;

  const timeEl = document.getElementById('def-obs-timestamp');
  if (timeEl) timeEl.textContent = formatTimestamp(obs.timestamp);

  const srcEl = document.getElementById('def-obs-source');
  if (srcEl) {
    const isReal = obs.source === 'hohenheim' || obs.is_recorded_playback;
    srcEl.textContent = isReal ? 'University of Hohenheim (Zenodo 15130001)' : 'Synthetic Simulator';
    srcEl.className = isReal ? 'badge badge-normal' : 'badge badge-low';
  }

  const sensors = obs.sensors || {};
  const dq = obs.data_quality || {};
  const activeCount = dq.active_sensor_count ?? Object.values(sensors).filter(s => s && s.temperature != null).length;
  const totalCount = dq.total_sensors ?? 9;

  const activeSensorsEl = document.getElementById('def-active-sensors');
  if (activeSensorsEl) activeSensorsEl.textContent = `${activeCount} / ${totalCount} Active`;

  const deltaTEl = document.getElementById('def-spatial-delta');
  if (deltaTEl) deltaTEl.textContent = `ΔT: ${formatNullableNumber(dq.inter_sensor_temp_delta, 1, '°C', '0.0°C')}`;

  // 9-Sensor Received Array
  const matrixEl = document.getElementById('sensor-matrix');
  if (!matrixEl) return;

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

// 2. Render joint decision verdict
function renderSecurityDecision(analysis) {
  if (!analysis) return;
  const dec = analysis.decision || {};

  const verdictEl = document.getElementById('joint-classification');
  if (verdictEl) {
    const cls = dec.classification || 'NORMAL';
    verdictEl.innerHTML = `<span class="badge ${getBadgeClass(cls)}" style="font-size: 0.85rem; padding: 0.3rem 0.75rem;">${cls}</span>`;
  }

  const riskEl = document.getElementById('joint-risk');
  if (riskEl) riskEl.textContent = `Risk Score: ${formatNullableNumber(dec.risk_score, 3, '', '0.000')}`;

  const integrityEl = document.getElementById('joint-integrity');
  if (integrityEl) integrityEl.textContent = `Integrity: ${formatNullableNumber(dec.integrity_score, 1, '%', '100.0%')}`;

  const expEl = document.getElementById('joint-explanation');
  if (expEl) expEl.textContent = dec.explanation || 'Operational records, IoT telemetry, and multi-sensor readings are internally consistent.';

  const bannerEl = document.getElementById('joint-decision-banner');
  if (bannerEl) {
    const cls = String(dec.classification || 'NORMAL').toUpperCase();
    if (cls === 'POTENTIAL_ATTACK' || cls === 'COORDINATED_ATTACK') {
      bannerEl.className = 'decision-banner violation';
    } else if (cls === 'SUSPICIOUS') {
      bannerEl.className = 'decision-banner warning';
    } else {
      bannerEl.className = 'decision-banner';
    }
  }
}

// 3. Render 5 detection layers
function renderDetectionLayers(analysis) {
  if (!analysis) return;
  const ml = analysis.ml || {};
  const sem = analysis.semantic || {};
  const temp = analysis.temporal || {};
  const struct = analysis.structural || {};

  // Layer 1: ML IsolationForest
  const mlStatus = document.getElementById('ml-status');
  if (mlStatus) mlStatus.innerHTML = `<span class="badge ${getBadgeClass(ml.status)}">${ml.status || 'NORMAL'}</span>`;
  const mlScore = document.getElementById('ml-score');
  if (mlScore) mlScore.textContent = formatNullableNumber(ml.anomaly_score, 3, '', '0.000');
  const mlFlag = document.getElementById('ml-flag');
  if (mlFlag) {
    mlFlag.textContent = ml.is_anomaly ? 'TRUE (Anomaly Detected)' : 'FALSE (Within Normal Bounds)';
    mlFlag.style.color = ml.is_anomaly ? '#f87171' : '#34d399';
  }
  const mlMode = document.getElementById('ml-mode');
  if (mlMode) mlMode.textContent = ml.model_mode || 'environmental_multisensor';
  const mlFeatures = document.getElementById('ml-features');
  if (mlFeatures) mlFeatures.textContent = (ml.features_evaluated || []).join(', ') || 'temperature, humidity, delta_t, delta_h, std_t';

  // Layer 2: Temporal Continuity
  const tempStatus = document.getElementById('temp-status');
  if (tempStatus) tempStatus.innerHTML = `<span class="badge ${getBadgeClass(temp.status)}">${temp.status || 'STABLE'}</span>`;
  const tempScore = document.getElementById('temp-score');
  if (tempScore) tempScore.textContent = formatNullableNumber(temp.temporal_score, 2, '', '0.00');
  const tempPers = document.getElementById('temp-persistence');
  if (tempPers) tempPers.textContent = `${temp.persistence || 0} consecutive intervals`;
  const tempRecurr = document.getElementById('temp-recurrence');
  if (tempRecurr) tempRecurr.textContent = `${temp.recurrence || 0} / 10 observations`;

  // Layer 3: Semantic Invariants C1-C4
  const semStatus = document.getElementById('sem-status');
  if (semStatus) semStatus.innerHTML = `<span class="badge ${getBadgeClass(sem.status)}">${sem.status || 'NORMAL'}</span>`;
  const semScore = document.getElementById('sem-score');
  if (semScore) semScore.textContent = formatNullableNumber(sem.semantic_score, 2, '', '0.00');

  const constraints = sem.constraints || [];
  const c1 = constraints.find(c => c.constraint === 'C1');
  const c2 = constraints.find(c => c.constraint === 'C2');
  const c3 = constraints.find(c => c.constraint === 'C3');
  const c4 = constraints.find(c => c.constraint === 'C4');

  const c1El = document.getElementById('c1-block');
  if (c1El && c1) {
    c1El.innerHTML = `
      <div class="constraint-header">
        <span style="font-weight: 700;">C1: Capacity Consistency</span>
        <span class="badge ${getBadgeClass(c1.status)}">${c1.status}</span>
      </div>
      <div style="font-size: 0.75rem; color: #94a3b8; margin-top: 0.2rem;">Inventory ledger fields not present in environmental dataset.</div>
      <div style="font-size: 0.72rem; color: var(--text-secondary); margin-top: 0.25rem;">${c1.message}</div>
    `;
  }

  const c2El = document.getElementById('c2-block');
  if (c2El && c2) {
    c2El.innerHTML = `
      <div class="constraint-header">
        <span style="font-weight: 700;">C2: Inbound/Outbound Mass Conservation</span>
        <span class="badge ${getBadgeClass(c2.status)}">${c2.status}</span>
      </div>
      <div style="font-size: 0.75rem; color: #94a3b8; margin-top: 0.2rem;">Shipment transfer ledgers not present in environmental dataset.</div>
      <div style="font-size: 0.72rem; color: var(--text-secondary); margin-top: 0.25rem;">${c2.message}</div>
    `;
  }

  const c3El = document.getElementById('c3-block');
  if (c3El && c3) {
    const actTemp = c3.actual && c3.actual.temperature != null ? formatNullableNumber(c3.actual.temperature, 1, '°C') : '--';
    const actHum = c3.actual && c3.actual.humidity != null ? formatNullableNumber(c3.actual.humidity, 1, '%') : '--';
    c3El.innerHTML = `
      <div class="constraint-header">
        <span style="font-weight: 700;">C3: Physical Thermal & Moisture Envelope</span>
        <span class="badge ${getBadgeClass(c3.status)}">${c3.status}</span>
      </div>
      <div style="font-size: 0.8rem; margin-top: 0.2rem;"><strong>Actual Readings:</strong> Temp = ${actTemp}, Humidity = ${actHum}</div>
      <div style="font-size: 0.72rem; color: var(--text-secondary); margin-top: 0.25rem;">${c3.message}</div>
    `;
  }

  const c4El = document.getElementById('c4-block');
  if (c4El && c4) {
    c4El.innerHTML = `
      <div class="constraint-header">
        <span style="font-weight: 700;">C4: Spatial Multi-Sensor Gradient</span>
        <span class="badge ${getBadgeClass(c4.status)}">${c4.status}</span>
      </div>
      <div style="font-size: 0.8rem; margin-top: 0.2rem;"><strong>Inter-Sensor ΔT:</strong> ${formatNullableNumber(c4.actual, 1, '°C')} (Maximum Allowed: ${formatNullableNumber(c4.expected, 1, '°C')})</div>
      <div style="font-size: 0.72rem; color: var(--text-secondary); margin-top: 0.25rem;">${c4.message}</div>
    `;
  }

  // Layer 4: Structural Graph Correlation
  const structStatus = document.getElementById('struct-status');
  if (structStatus) structStatus.innerHTML = `<span class="badge ${getBadgeClass(struct.status)}">${struct.status || 'ISOLATED'}</span>`;
  const structScore = document.getElementById('struct-score');
  if (structScore) structScore.textContent = formatNullableNumber(struct.structural_score, 2, '', '0.00');
  const structNodes = document.getElementById('struct-nodes');
  if (structNodes) {
    structNodes.textContent = (struct.affected_nodes || []).length > 0 ? struct.affected_nodes.join(', ') : 'None (Isolated)';
  }
  const structEdges = document.getElementById('struct-edges');
  if (structEdges) {
    structEdges.textContent = (struct.correlated_edges || []).length > 0 ? struct.correlated_edges.map(e => e.join(' ↔ ')).join('; ') : 'None';
  }
}

// 4. Render SHA-256 Cryptographic Audit Chain
function renderAuditChain(audit) {
  const auditValid = document.getElementById('audit-valid-status');
  if (auditValid) {
    auditValid.textContent = audit.valid ? 'VERIFIED INTACT (SHA-256)' : 'TAMPER DETECTED';
    auditValid.style.color = audit.valid ? '#10b981' : '#ef4444';
  }
  const auditBadge = document.getElementById('kpi-audit-chain');
  if (auditBadge) {
    auditBadge.innerHTML = `<span class="badge ${audit.valid ? 'badge-normal' : 'badge-potential_attack'}">${audit.valid ? 'SHA-256 INTACT' : 'TAMPERED'}</span>`;
  }
  const auditEvents = document.getElementById('audit-events-count');
  if (auditEvents) auditEvents.textContent = `${audit.total_events || 0} Cryptographically Linked Blocks`;
  const auditHash = document.getElementById('audit-latest-hash');
  if (auditHash) auditHash.textContent = audit.latest_event_hash || 'GENESIS';
}

function toggleRawEvidence() {
  const body = document.getElementById('expandable-raw-body');
  const icon = document.getElementById('raw-evidence-toggle-icon');
  if (!body || !icon) return;
  const isHidden = body.style.display === 'none';
  body.style.display = isHidden ? 'block' : 'none';
  icon.innerHTML = isHidden ? '&minus; Collapse' : '&plus; Expand';
}

// Initialization & periodic live polling
document.addEventListener('DOMContentLoaded', () => {
  refreshDefenderState();
  pollTimer = setInterval(refreshDefenderState, 3000);
});
