"""Controlled Attack Experiment Execution Engine.

Manages reproducible experiment runs, strictly separates ground-truth labels
from Defender inference inputs, calculates true/false positive/negative outcomes,
and computes empirical benchmark metrics without fabrication.
"""

from copy import deepcopy
import csv
from datetime import datetime, timezone
import io
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from app.api.state import app_state
from app.config import settings
from app.experiments.models import (
    AggregateMetrics,
    AttackConfiguration,
    ExperimentResult,
    ModifiedField,
)
from app.experiments.scenarios import SCENARIOS_CATALOG, apply_attack
from app.simulator.models import WarehouseObservation

logger = logging.getLogger("experiments.engine")


class ExperimentEngine:
    """Thread-safe controller for running baseline and attack evaluation experiments."""

    def __init__(self):
        self._lock = threading.RLock()
        self._history: List[ExperimentResult] = []
        self._experiment_counter: int = 0

    def _next_experiment_id(self) -> str:
        with self._lock:
            self._experiment_counter += 1
            return f"EXP-{self._experiment_counter:04d}"

    def _determine_outcome(self, expected_label: str, prediction: str, risk_score: float) -> str:
        """Evaluate detection classification against ground truth."""
        is_attack_expected = expected_label == "ATTACK"
        # Defender detection is positive if classified as attack, suspicious, or elevated risk
        is_detected = (
            prediction in ("POTENTIAL_ATTACK", "COORDINATED_ATTACK", "SUSPICIOUS")
            or risk_score >= settings.DECISION_SUSPICIOUS_RISK_THRESHOLD
        )

        if is_attack_expected:
            return "TRUE_POSITIVE" if is_detected else "FALSE_NEGATIVE"
        else:
            return "FALSE_POSITIVE" if is_detected else "TRUE_NEGATIVE"

    def _extract_contributing_layers(self, analysis: Any) -> List[str]:
        """Identify which detection layers contributed evidence to the decision."""
        layers = []
        ml = getattr(analysis, "ml", None)
        if ml and (ml.is_anomaly or ml.anomaly_score >= 0.60 or ml.status != "NORMAL"):
            layers.append(f"ML Outlier Detector (Score: {ml.anomaly_score:.3f})")

        sem = getattr(analysis, "semantic", None)
        if sem:
            for c in getattr(sem, "constraints", []):
                if c.status in ("VIOLATED", "WARNING"):
                    layers.append(f"{c.constraint} {c.name} ({c.status})")

        temp = getattr(analysis, "temporal", None)
        if temp and (temp.status != "STABLE" or temp.temporal_score >= 0.20):
            layers.append(f"Temporal Analysis (Persistence: {temp.persistence}, Score: {temp.temporal_score:.2f})")

        struct = getattr(analysis, "structural", None)
        if struct and (struct.status != "ISOLATED" or struct.structural_score >= 0.20):
            layers.append(f"Structural Graph Correlation (Score: {struct.structural_score:.2f})")

        if not layers:
            layers.append("Baseline Conformity (All Invariants Passed)")

        return layers

    def run_baseline(self, step: int = 0) -> ExperimentResult:
        """Run a normal baseline observation through the Defender without attack injection."""
        with self._lock:
            exp_id = self._next_experiment_id()
            now_iso = datetime.now(timezone.utc).isoformat()

            # Retrieve clean observation from active data source
            clean_obs = app_state.data_source.seek(step)
            orig_dict = clean_obs.model_dump()

            # Run through actual live Defender pipeline
            t0 = time.perf_counter()
            analysis = app_state.defender.analyze(clean_obs)
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)

            pred = analysis.decision.classification
            risk = analysis.decision.risk_score
            integrity = analysis.decision.integrity_score
            outcome = self._determine_outcome(expected_label="NORMAL", prediction=pred, risk_score=risk)
            contributing = self._extract_contributing_layers(analysis)

            result = ExperimentResult(
                experiment_id=exp_id,
                created_at=now_iso,
                step=step,
                timestamp=clean_obs.timestamp,
                is_attack=False,
                attack_type="baseline",
                target_sensor=None,
                parameters={"mode": "baseline_normal", "step": step},
                modified_fields=[],
                expected_label="NORMAL",
                defender_prediction=pred,
                outcome=outcome,
                detection_score=risk,
                integrity_score=integrity,
                detection_latency_ms=latency_ms,
                contributing_layers=contributing,
                explanation=analysis.decision.explanation,
                original_observation=orig_dict,
                modified_observation=orig_dict,
                security_analysis=analysis.model_dump(),
            )
            self._history.append(result)
            logger.info(f"Executed baseline experiment {exp_id} at step {step}: Outcome={outcome}, Score={risk:.3f}")
            return result

    def run_attack_experiment(self, step: int, config: AttackConfiguration) -> ExperimentResult:
        """Inject a controlled attack into an observation copy and evaluate with Defender."""
        with self._lock:
            exp_id = self._next_experiment_id()
            now_iso = datetime.now(timezone.utc).isoformat()

            # Retrieve baseline observation (original dataset remains untouched)
            baseline_obs = app_state.data_source.seek(step)
            orig_dict = baseline_obs.model_dump()

            # For replay attacks, retrieve historical observation
            past_obs = None
            if config.scenario == "replay_substitution":
                r_step = config.replay_step if config.replay_step is not None else max(0, step - 30)
                try:
                    past_obs = app_state.data_source.seek(r_step)
                    # Restore cursor back to target step
                    app_state.data_source.seek(step)
                except Exception as exc:
                    logger.warning(f"Could not load replay step {r_step}: {exc}")

            # Apply attack transformation to independent observation copy
            modified_obs, modified_fields = apply_attack(baseline_obs, config, past_obs=past_obs)
            mod_dict = modified_obs.model_dump()

            # Ground truth is strictly NOT leaked to DefenderService!
            # The observation passed has is_attack_injected=False and attack_type=None.
            t0 = time.perf_counter()
            analysis = app_state.defender.analyze(modified_obs)
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)

            pred = analysis.decision.classification
            risk = analysis.decision.risk_score
            integrity = analysis.decision.integrity_score
            outcome = self._determine_outcome(expected_label="ATTACK", prediction=pred, risk_score=risk)
            contributing = self._extract_contributing_layers(analysis)

            result = ExperimentResult(
                experiment_id=exp_id,
                created_at=now_iso,
                step=step,
                timestamp=baseline_obs.timestamp,
                is_attack=True,
                attack_type=config.scenario,
                target_sensor=config.target_sensor,
                parameters=config.model_dump(),
                modified_fields=modified_fields,
                expected_label="ATTACK",
                defender_prediction=pred,
                outcome=outcome,
                detection_score=risk,
                integrity_score=integrity,
                detection_latency_ms=latency_ms,
                contributing_layers=contributing,
                explanation=analysis.decision.explanation,
                original_observation=orig_dict,
                modified_observation=mod_dict,
                security_analysis=analysis.model_dump(),
            )
            self._history.append(result)
            logger.info(
                f"Executed attack experiment {exp_id} ({config.scenario} on {config.target_sensor}): "
                f"Expected=ATTACK, Predicted={pred}, Outcome={outcome}, Score={risk:.3f}"
            )
            return result

    def get_history(
        self,
        limit: int = 100,
        attack_type: Optional[str] = None,
        outcome: Optional[str] = None,
        target_sensor: Optional[str] = None,
    ) -> List[ExperimentResult]:
        """Retrieve recorded experiments with optional multi-attribute filtering."""
        with self._lock:
            filtered = list(self._history)

            if attack_type and attack_type.lower() != "all":
                clean_at = attack_type.lower().strip()
                filtered = [r for r in filtered if r.attack_type.lower() == clean_at]

            if outcome and outcome.upper() != "ALL":
                clean_out = outcome.upper().strip()
                filtered = [r for r in filtered if r.outcome == clean_out]

            if target_sensor and target_sensor.upper() != "ALL":
                clean_sensor = target_sensor.upper().strip()
                filtered = [r for r in filtered if r.target_sensor == clean_sensor]

            # Return reverse chronological order (newest first)
            filtered.reverse()
            return filtered[:limit] if limit > 0 else filtered

    def get_experiment_by_id(self, experiment_id: str) -> Optional[ExperimentResult]:
        with self._lock:
            for exp in self._history:
                if exp.experiment_id == experiment_id:
                    return exp
            return None

    def compute_metrics(self) -> AggregateMetrics:
        """Compute precision, recall, F1, FPR, accuracy, and per-attack breakdown."""
        with self._lock:
            total = len(self._history)
            if total == 0:
                return AggregateMetrics()

            tp = sum(1 for r in self._history if r.outcome == "TRUE_POSITIVE")
            tn = sum(1 for r in self._history if r.outcome == "TRUE_NEGATIVE")
            fp = sum(1 for r in self._history if r.outcome == "FALSE_POSITIVE")
            fn = sum(1 for r in self._history if r.outcome == "FALSE_NEGATIVE")

            precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else None
            recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else None

            f1 = None
            if precision is not None and recall is not None and (precision + recall) > 0:
                f1 = round(2 * (precision * recall) / (precision + recall), 4)

            fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else None
            acc = round((tp + tn) / total, 4) if total > 0 else None
            avg_latency = round(sum(r.detection_latency_ms for r in self._history) / total, 2)

            # Per-attack class metrics
            breakdown: Dict[str, Dict[str, Any]] = {}
            for sc_id in list(SCENARIOS_CATALOG.keys()) + ["baseline"]:
                sc_records = [r for r in self._history if r.attack_type == sc_id]
                if sc_records:
                    sc_tp = sum(1 for r in sc_records if r.outcome in ("TRUE_POSITIVE", "TRUE_NEGATIVE"))
                    sc_total = len(sc_records)
                    sc_rate = round(sc_tp / sc_total, 4) if sc_total > 0 else 0.0
                    breakdown[sc_id] = {
                        "total_samples": sc_total,
                        "correctly_classified": sc_tp,
                        "success_rate": sc_rate,
                        "avg_risk_score": round(sum(r.detection_score for r in sc_records) / sc_total, 3),
                        "avg_latency_ms": round(sum(r.detection_latency_ms for r in sc_records) / sc_total, 2),
                    }

            return AggregateMetrics(
                total_experiments=total,
                true_positives=tp,
                true_negatives=tn,
                false_positives=fp,
                false_negatives=fn,
                precision=precision,
                recall=recall,
                f1_score=f1,
                false_positive_rate=fpr,
                accuracy=acc,
                avg_latency_ms=avg_latency,
                per_attack_breakdown=breakdown,
            )

    def export_csv(self) -> str:
        """Export all experiment results in RFC 4180 compliant CSV format."""
        with self._lock:
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "Experiment ID",
                "Created At",
                "Step",
                "Timestamp",
                "Is Attack",
                "Attack Scenario",
                "Target Sensor",
                "Expected Label",
                "Defender Prediction",
                "Outcome",
                "Detection Score",
                "Integrity Score",
                "Latency (ms)",
                "Modified Fields Count",
                "Contributing Layers",
                "Explanation",
            ])

            for r in self._history:
                layers_str = "; ".join(r.contributing_layers)
                writer.writerow([
                    r.experiment_id,
                    r.created_at,
                    r.step,
                    r.timestamp,
                    r.is_attack,
                    r.attack_type,
                    r.target_sensor or "N/A",
                    r.expected_label,
                    r.defender_prediction,
                    r.outcome,
                    r.detection_score,
                    r.integrity_score,
                    r.detection_latency_ms,
                    len(r.modified_fields),
                    layers_str,
                    r.explanation,
                ])

            return output.getvalue()

    def get_reproducibility_record(self, experiment_id: str) -> Optional[Dict[str, Any]]:
        """Generate a complete self-contained reproducibility audit package."""
        exp = self.get_experiment_by_id(experiment_id)
        if not exp:
            return None

        return {
            "experiment_id": exp.experiment_id,
            "provenance": {
                "dataset_title": "Temperature and Humidity Time Series of Cold Storage Room Monitoring",
                "dataset_doi": "10.5281/zenodo.15130001",
                "dataset_license": "Creative Commons Attribution 4.0 International (CC-BY-4.0)",
                "dataset_url": "https://zenodo.org/records/15130001",
                "detector_version": settings.APP_VERSION,
                "project": "Cold-Storage Security Monitor (Team 12, VIT CSBS)",
            },
            "parameters": exp.parameters,
            "ground_truth_label": exp.expected_label,
            "modified_fields": [m.model_dump() for m in exp.modified_fields],
            "original_observation": exp.original_observation,
            "modified_observation": exp.modified_observation,
            "defender_prediction": exp.defender_prediction,
            "outcome": exp.outcome,
            "detection_score": exp.detection_score,
            "contributing_layers": exp.contributing_layers,
            "reproducibility_python_snippet": (
                f"# Reproduce Experiment {exp.experiment_id}\n"
                f"from app.api.state import app_state\n"
                f"from app.experiments.models import AttackConfiguration\n"
                f"from app.experiments.scenarios import apply_attack\n\n"
                f"obs = app_state.data_source.seek({exp.step})\n"
                f"config = AttackConfiguration(**{exp.parameters})\n"
                f"mod_obs, _ = apply_attack(obs, config)\n"
                f"result = app_state.defender.analyze(mod_obs)\n"
                f"print('Classification:', result.decision.classification)\n"
                f"print('Risk Score:', result.decision.risk_score)\n"
            ),
        }

    def reset(self) -> None:
        """Clear recorded experiment history and reset counter."""
        with self._lock:
            self._history.clear()
            self._experiment_counter = 0
            logger.info("Cleared experiment history and reset counter.")


# Global experiment engine instance
experiment_engine = ExperimentEngine()
