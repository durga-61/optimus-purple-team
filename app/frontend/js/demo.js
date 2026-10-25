/* ==========================================================================
   Cold-Storage Security Monitor — Demo Sandbox Controller (demo.js)
   Enterprise cybersecurity research sandbox logic.
   ========================================================================== */

const API_BASE = '/api';

// State management
let isCompactDensity = false;
let currentMode = 'live'; // 'live' | 'attack_preview' | 'normal_preview'
let currentTheme = 'light'; // Default to light theme

// Default authentic Hohenheim Step 0 telemetry
const defaultSensors = [
  { id: 'SENSOR01', role: 'Ambient Room Central', temp: 21.2, hum: 62.5, isDropout: false },
  { id: 'SENSOR02', role: 'Ambient Validation', temp: 22.1, hum: 63.4, isDropout: false },
  { id: 'SENSOR03', role: 'Storage Corner (Fixed)', temp: null, hum: null, isDropout: true },
  { id: 'SENSOR04', role: 'Wall-Mounted Monitor', temp: 21.9, hum: 60.9, isDropout: false },
  { id: 'SENSOR05', role: 'Mobile Experimental Unit', temp: null, hum: null, isDropout: true },
  { id: 'SENSOR06', role: 'Ambient Facility Monitor', temp: 22.1, hum: 58.6, isDropout: false },
  { id: 'SENSOR07', role: 'Door Entry Perimeter', temp: 22.8, hum: 66.9, isDropout: false },
  { id: 'SENSOR08', role: 'Cooling Unit Evaporator', temp: 21.6, hum: 62.4, isDropout: false },
  { id: 'SENSOR09', role: 'Mobile Temperature Probe', temp: null, hum: null, isDropout: true },
];

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initClock();
  renderSensors(defaultSensors);
  fetchLiveTelemetry().then(() => {
    // Check URL parameters for initial sandbox preview states
    const params = new URLSearchParams(window.location.search);
    if (params.get('density') === 'compact') {
      toggleDensity('compact');
    }
    if (params.get('simulate') === 'attack') {
      simulateAttack();
    }
  });
  setupEventListeners();
});

// 0. Theme Management (Light as Default, Dynamic Dark Toggle)
function initTheme() {
  const params = new URLSearchParams(window.location.search);
  const paramTheme = params.get('theme');
  const storedTheme = localStorage.getItem('optimus-theme');
  const initialTheme = paramTheme || storedTheme || 'light';
  setTheme(initialTheme);
}

function setTheme(theme) {
  currentTheme = theme === 'dark' ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', currentTheme);
  try {
    localStorage.setItem('optimus-theme', currentTheme);
  } catch (e) {
    // Ignore localStorage restrictions if any
  }

  // Update header buttons
  const btnLight = document.getElementById('btn-theme-light');
  const btnDark = document.getElementById('btn-theme-dark');
  if (btnLight && btnDark) {
    if (currentTheme === 'light') {
      btnLight.classList.add('active');
      btnDark.classList.remove('active');
    } else {
      btnDark.classList.add('active');
      btnLight.classList.remove('active');
    }
  }

  // Update toolbar buttons
  const tbLight = document.getElementById('btn-toolbar-theme-light');
  const tbDark = document.getElementById('btn-toolbar-theme-dark');
  if (tbLight && tbDark) {
    if (currentTheme === 'light') {
      tbLight.classList.add('active');
      tbDark.classList.remove('active');
    } else {
      tbDark.classList.add('active');
      tbLight.classList.remove('active');
    }
  }
}

// 1. UTC Real-Time Clock
function initClock() {
  const clockEl = document.getElementById('demo-utc-clock');
  function update() {
    if (clockEl) {
      const now = new Date();
      clockEl.textContent = now.toISOString().substring(11, 19) + ' UTC';
    }
  }
  update();
  setInterval(update, 1000);
}

// 2. Render 9-Sensor Matrix
function renderSensors(sensorList) {
  const container = document.getElementById('demo-telemetry-grid');
  if (!container) return;

  container.innerHTML = sensorList.map(s => `
    <div class="sensor-card ${s.isDropout ? 'dropout' : ''}" id="card-${s.id}">
      <div class="sensor-card-header">
        <span class="sensor-id">${s.id}</span>
        ${s.isDropout 
          ? `<span class="badge badge-na">DROPOUT</span>` 
          : `<span class="badge badge-normal">ACTIVE</span>`}
      </div>
      <div class="sensor-role" title="${s.role}">${s.role}</div>
      <div class="sensor-readouts">
        <span class="val-temp" id="val-t-${s.id}">
          ${s.temp != null ? `${Number(s.temp).toFixed(1)} °C` : '<span style="color:var(--text-muted);font-weight:normal;">--</span>'}
        </span>
        <span class="val-hum" id="val-h-${s.id}">
          ${s.hum != null ? `${Number(s.hum).toFixed(1)} %` : '<span style="color:var(--text-muted);font-weight:normal;">--</span>'}
        </span>
      </div>
    </div>
  `).join('');
}

// 3. Fetch Live Telemetry from API
async function fetchLiveTelemetry() {
  try {
    const res = await fetch(`${API_BASE}/warehouse/current`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    const sensors = data.sensors || {};
    const updated = defaultSensors.map(s => {
      const live = sensors[s.id];
      const isMissing = !live || live.temperature == null || live.is_missing;
      if (isMissing) {
        return { ...s, temp: null, hum: null, isDropout: true };
      }
      return {
        ...s,
        temp: live.temperature,
        hum: live.humidity,
        isDropout: false,
      };
    });

    renderSensors(updated);
    setConnectionStatus(true);
  } catch (err) {
    console.warn('API fetch fell back to deterministic baseline:', err.message);
    setConnectionStatus(false);
  }
}

function setConnectionStatus(online) {
  const dot = document.getElementById('demo-status-dot');
  const label = document.getElementById('demo-status-label');
  if (dot && label) {
    if (online) {
      dot.style.backgroundColor = 'var(--status-normal)';
      label.textContent = 'API CONNECTED';
    } else {
      dot.style.backgroundColor = 'var(--status-warning)';
      label.textContent = 'SANDBOX OFFLINE';
    }
  }
}

// 4. Interactive Simulation Modes
function simulateNormalBaseline() {
  currentMode = 'normal_preview';
  const banner = document.getElementById('demo-verdict-banner');
  const badge = document.getElementById('demo-verdict-badge');
  const desc = document.getElementById('demo-verdict-desc');
  const risk = document.getElementById('demo-risk-val');
  const integ = document.getElementById('demo-integrity-val');
  const diffRow = document.getElementById('diff-preview-row');

  if (banner) banner.className = 'verdict-banner';
  if (badge) {
    badge.className = 'badge badge-normal';
    badge.textContent = 'NORMAL';
  }
  if (desc) desc.textContent = 'Operational records, physical multi-sensor readings, and ledger streams satisfy all invariants.';
  if (risk) risk.textContent = '0.045';
  if (integ) integ.textContent = '96.5 %';

  // Restore sensor readings
  renderSensors(defaultSensors);

  if (diffRow) {
    diffRow.innerHTML = `
      <td class="diff-orig" style="color:var(--text-primary);font-weight:600;">SENSOR01</td>
      <td>Temperature</td>
      <td class="diff-orig">21.2 °C</td>
      <td class="diff-mod">21.2 °C</td>
      <td class="diff-delta" style="color:var(--status-normal);">0.0 °C (Identical)</td>
    `;
  }

  // Restore layer badges
  updateLayer('ml', 'NORMAL', '0.082', 'Within Normal Profile');
  updateLayer('temp', 'STABLE', '0.00', 'Consecutive Violations: 0');
  updateLayer('sem', 'NORMAL', '0.00', 'All Invariants Satisfied');
  updateLayer('struct', 'ISOLATED', '0.00', 'No Cross-Subsystem Leakage');
  updateLayer('audit', 'INTACT', 'SHA-256', 'Genesis Hash Chained');
}

function simulateAttack() {
  currentMode = 'attack_preview';
  const banner = document.getElementById('demo-verdict-banner');
  const badge = document.getElementById('demo-verdict-badge');
  const desc = document.getElementById('demo-verdict-desc');
  const risk = document.getElementById('demo-risk-val');
  const integ = document.getElementById('demo-integrity-val');
  const diffRow = document.getElementById('diff-preview-row');

  if (banner) banner.className = 'verdict-banner state-attack';
  if (badge) {
    badge.className = 'badge badge-attack';
    badge.textContent = 'ATTACK';
  }
  if (desc) desc.textContent = 'Single-point temperature manipulation detected: thermal envelope (C3) & spatial gradient limit (C4) violated.';
  if (risk) risk.textContent = '0.942';
  if (integ) integ.textContent = '14.2 %';

  // Mutate SENSOR01 in the grid
  const mutated = defaultSensors.map(s => {
    if (s.id === 'SENSOR01') {
      return { ...s, temp: 33.2 };
    }
    return s;
  });
  renderSensors(mutated);

  // Highlight card SENSOR01
  const card = document.getElementById('card-SENSOR01');
  if (card) {
    card.style.borderColor = 'var(--status-attack)';
  }

  if (diffRow) {
    diffRow.innerHTML = `
      <td class="diff-orig" style="color:var(--text-primary);font-weight:600;">SENSOR01</td>
      <td>Temperature</td>
      <td class="diff-orig">21.2 °C</td>
      <td class="diff-mod" style="color:var(--status-attack);">33.2 °C</td>
      <td class="diff-delta pos">+12.0 °C (Anomaly)</td>
    `;
  }

  // Update layer badges to reflect attack detection
  updateLayer('ml', 'ATTACK', '0.962', 'IsolationForest Anomaly');
  updateLayer('temp', 'SUSPICIOUS', '0.45', 'Abrupt Jump (>5°C/5s)');
  updateLayer('sem', 'VIOLATION', '1.00', 'C3 Out-of-Bounds & C4 ΔT Spike');
  updateLayer('struct', 'CORRELATED', '0.85', 'Sensor 01 Dependency Node Active');
  updateLayer('audit', 'INTACT', 'SHA-256', 'Tamper Evident Record Stored');
}

function updateLayer(layerId, badgeText, scoreVal, descVal) {
  const b = document.getElementById(`badge-layer-${layerId}`);
  const s = document.getElementById(`score-layer-${layerId}`);
  const d = document.getElementById(`desc-layer-${layerId}`);

  if (b) {
    b.textContent = badgeText;
    if (badgeText === 'ATTACK' || badgeText === 'VIOLATION') b.className = 'badge badge-attack';
    else if (badgeText === 'SUSPICIOUS') b.className = 'badge badge-warning';
    else b.className = 'badge badge-normal';
  }
  if (s) s.textContent = scoreVal;
  if (d) d.textContent = descVal;
}

// 5. Density Mode Toggle
function toggleDensity(mode) {
  const btnStd = document.getElementById('btn-density-standard');
  const btnCpt = document.getElementById('btn-density-compact');

  if (mode === 'compact') {
    document.body.classList.add('density-compact');
    if (btnCpt) btnCpt.classList.add('active');
    if (btnStd) btnStd.classList.remove('active');
    isCompactDensity = true;
  } else {
    document.body.classList.remove('density-compact');
    if (btnStd) btnStd.classList.add('active');
    if (btnCpt) btnCpt.classList.remove('active');
    isCompactDensity = false;
  }
}

// 6. Setup Event Listeners
function setupEventListeners() {
  const btnNormal = document.getElementById('btn-test-normal');
  const btnAttack = document.getElementById('btn-test-attack');
  const btnLive = document.getElementById('btn-revert-live');

  if (btnNormal) btnNormal.addEventListener('click', simulateNormalBaseline);
  if (btnAttack) btnAttack.addEventListener('click', simulateAttack);
  if (btnLive) btnLive.addEventListener('click', () => {
    simulateNormalBaseline();
    fetchLiveTelemetry();
  });

  const btnStd = document.getElementById('btn-density-standard');
  const btnCpt = document.getElementById('btn-density-compact');
  if (btnStd) btnStd.addEventListener('click', () => toggleDensity('standard'));
  if (btnCpt) btnCpt.addEventListener('click', () => toggleDensity('compact'));

  // Theme switchers
  const btnLight = document.getElementById('btn-theme-light');
  const btnDark = document.getElementById('btn-theme-dark');
  const tbLight = document.getElementById('btn-toolbar-theme-light');
  const tbDark = document.getElementById('btn-toolbar-theme-dark');

  if (btnLight) btnLight.addEventListener('click', () => setTheme('light'));
  if (btnDark) btnDark.addEventListener('click', () => setTheme('dark'));
  if (tbLight) tbLight.addEventListener('click', () => setTheme('light'));
  if (tbDark) tbDark.addEventListener('click', () => setTheme('dark'));
}
