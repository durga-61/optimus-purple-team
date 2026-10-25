/**
 * Optimus — Shared Utilities and Client Communication Helpers
 * Used across Defender, Sensor Transmitter, and Attack Simulator portals.
 */

const API_BASE = '/api';

// Safe JSON fetch wrapper with error handling
async function fetchJson(url, options = {}) {
  const resp = await fetch(url, options);
  if (!resp.ok) {
    let errDetail = `${resp.status} ${resp.statusText}`;
    try {
      const errJson = await resp.json();
      errDetail = errJson.detail || errJson.message || errDetail;
    } catch (_) {}
    throw new Error(errDetail);
  }
  return await resp.json();
}

// Fmt nullable numbers honestly without fabrication
function formatNullableNumber(val, decimals = 1, unit = '', naText = '--') {
  if (val === null || val === undefined || isNaN(val)) return naText;
  const num = Number(val);
  return `${num.toFixed(decimals)}${unit ? ' ' + unit : ''}`;
}

// ISO 8601 UTC timestamp formatter
function formatTimestamp(isoStr) {
  if (!isoStr) return '--:--:-- UTC';
  try {
    const d = new Date(isoStr);
    if (isNaN(d.getTime())) return isoStr;
    return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
  } catch (_) {
    return isoStr;
  }
}

// Status badge CSS resolver
function getBadgeClass(status) {
  if (!status) return 'badge-normal';
  const s = String(status).toUpperCase();
  if (s === 'NORMAL' || s === 'STABLE' || s === 'PASSED' || s === 'PASS' || s === 'ONLINE' || s === 'DELIVERED') return 'badge-normal';
  if (s === 'LOW' || s === 'INFO') return 'badge-low';
  if (s === 'SUSPICIOUS' || s === 'WARNING' || s === 'DROPOUT') return 'badge-suspicious';
  if (s === 'POTENTIAL_ATTACK' || s === 'VIOLATION' || s === 'ANOMALY' || s === 'ATTACK') return 'badge-potential_attack';
  if (s === 'COORDINATED_ATTACK' || s === 'ERROR' || s === 'FAILED') return 'badge-coordinated_attack';
  if (s === 'NOT_APPLICABLE' || s === 'N/A' || s === 'INSUFFICIENT_DATA') return 'badge-na';
  return 'badge-normal';
}

// Empirical outcome class resolver
function getOutcomeClass(outcome) {
  if (!outcome) return 'outcome-tn';
  const o = String(outcome).toUpperCase();
  if (o.includes('TRUE_POSITIVE') || o === 'TP') return 'outcome-tp';
  if (o.includes('TRUE_NEGATIVE') || o === 'TN') return 'outcome-tn';
  if (o.includes('FALSE_POSITIVE') || o === 'FP') return 'outcome-fp';
  if (o.includes('FALSE_NEGATIVE') || o === 'FN') return 'outcome-fn';
  return 'outcome-tn';
}

// Standard Hohenheim Sensor Roles
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

// Global clock updater
function initGlobalClock() {
  const clockEl = document.getElementById('current-time');
  if (!clockEl) return;
  const update = () => {
    const now = new Date();
    clockEl.textContent = now.toISOString().substring(11, 19) + ' UTC';
  };
  update();
  setInterval(update, 1000);
}

document.addEventListener('DOMContentLoaded', initGlobalClock);
