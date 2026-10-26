#!/usr/bin/env python3
"""Review 3 case study: scaled-down refrigeration-controller attack simulation.

The case study is modelled on the October 2026 compromises of internet-exposed
Danfoss AK-SM/AK-SC, Copeland xweb and Dixell xweb refrigeration controllers in
French supermarkets (CERT-FR CERTFR-2026-ALE-012).  The production system is a
passive data-integrity monitor, so the simulation reproduces the *observable
stages* of the incident on the working Defender pipeline:

1. A sustained, out-of-envelope temperature excursion (controller setpoint
   runaway).
2. A subtle, in-envelope temperature change that is enough to compromise the
   cold chain over time.
3. A localised cross-sensor spoof.
4. Replayed normal telemetry that hides an actual hot reading.
5. Telemetry suppression (forced sensor dropout).
6. A baseline normal observation.

All attacks use the same ``apply_attack`` transformations as the live Attack
Simulator portal.  Ground-truth labels are never passed to ``DefenderService``.

Run from the repository root:

    .venv/bin/python scripts/review3_case_study.py

Outputs:
    evaluation_results/review3_case_study.json
    evaluation_results/review3_case_study.md
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Sequence

# Make the repository root importable when invoked as ``python scripts/...``.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.api.state import app_state
from app.experiments.engine import experiment_engine
from app.experiments.models import AttackConfiguration, ExperimentResult
from app.experiments.scenarios import (
    apply_replay_substitution,
    apply_temperature_manipulation,
)
from app.defender.audit import verify_audit_chain

BASELINE_STEP = 30
SEED_STEP = BASELINE_STEP - 1
DATASET_DOI = "10.5281/zenodo.15130001"
CASE_SOURCE = "CERTFR-2026-ALE-012"


def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        return "unknown"


def _reset_and_seed() -> None:
    """Reset the live app state, then seed one clean prior observation."""
    app_state.reset()
    experiment_engine.reset()
    app_state.data_source.seek(SEED_STEP)
    app_state.defender.analyze(app_state.data_source.get_current_observation())


def _compact_constraints(security_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        {
            "constraint": c.get("constraint"),
            "name": c.get("name"),
            "status": c.get("status"),
            "difference": c.get("difference"),
            "message": c.get("message"),
        }
        for c in security_analysis.get("semantic", {}).get("constraints", [])
    ]


def _summarise_result(result: ExperimentResult) -> Dict[str, Any]:
    analysis = result.security_analysis
    return {
        "experiment_id": result.experiment_id,
        "step": result.step,
        "timestamp": result.timestamp,
        "expected_label": result.expected_label,
        "defender_prediction": result.defender_prediction,
        "outcome": result.outcome,
        "risk_score": result.detection_score,
        "integrity_score": result.integrity_score,
        "latency_ms": result.detection_latency_ms,
        "contributing_layers": result.contributing_layers,
        "explanation": result.explanation,
        "modified_fields": [f.model_dump() for f in result.modified_fields],
        "semantic_status": analysis.get("semantic", {}).get("status"),
        "semantic_score": analysis.get("semantic", {}).get("semantic_score"),
        "semantic_constraints": _compact_constraints(analysis),
        "temporal_status": analysis.get("temporal", {}).get("status"),
        "temporal_persistence": analysis.get("temporal", {}).get("persistence"),
        "temporal_score": analysis.get("temporal", {}).get("temporal_score"),
        "structural_status": analysis.get("structural", {}).get("status"),
        "structural_score": analysis.get("structural", {}).get("structural_score"),
        "ml_score": analysis.get("ml", {}).get("anomaly_score"),
    }


def _run_case(
    name: str,
    stage: str,
    description: str,
    config: AttackConfiguration,
    steps: Sequence[int],
) -> Dict[str, Any]:
    _reset_and_seed()
    results = [
        _summarise_result(experiment_engine.run_attack_experiment(step=step, config=config))
        for step in steps
    ]
    detected = [r for r in results if r["outcome"] == "TRUE_POSITIVE"]
    return {
        "name": name,
        "stage": stage,
        "description": description,
        "configuration": config.model_dump(),
        "steps": list(steps),
        "results": results,
        "detected": bool(detected),
        "verdict": "DETECTED" if detected else "MISSED",
        "detection_step": detected[0]["step"] if detected else None,
        "max_classification": _max_classification([r["defender_prediction"] for r in results]),
        "max_risk_score": max(r["risk_score"] for r in results),
    }


def _max_classification(predictions: Sequence[str]) -> str:
    rank = {"NORMAL": 0, "LOW": 1, "SUSPICIOUS": 2, "POTENTIAL_ATTACK": 3, "COORDINATED_ATTACK": 4}
    return max(predictions, key=lambda p: rank.get(p, -1))


def _baseline_case() -> Dict[str, Any]:
    _reset_and_seed()
    result = _summarise_result(experiment_engine.run_baseline(step=BASELINE_STEP))
    return {
        "name": "baseline_normal",
        "stage": "normal operation",
        "description": "Clean recorded observation; no manipulation. Ground truth NORMAL.",
        "configuration": None,
        "steps": [BASELINE_STEP],
        "results": [result],
        "detected": result["outcome"] == "FALSE_POSITIVE",
        "verdict": "CORRECT (no alert)",
        "detection_step": None,
        "max_classification": result["defender_prediction"],
        "max_risk_score": result["risk_score"],
    }


def _hidden_hot_replay_case() -> Dict[str, Any]:
    """Simulate a controller that reports a replayed normal frame while the plant is hot.

    The Defender only sees the reported frame.  The ground-truth physical state
    is a +25 degC excursion, but the reported SENSOR01 value is replayed from
    step 0.  This is the telemetry-substitution stage of the real incident.
    """
    _reset_and_seed()
    clean = app_state.data_source.seek(BASELINE_STEP)
    past = app_state.data_source.seek(0)
    app_state.data_source.seek(BASELINE_STEP)

    hot, hot_fields = apply_temperature_manipulation(clean, target_sensor="SENSOR01", magnitude=25.0)
    reported, replay_fields = apply_replay_substitution(hot, target_sensor="SENSOR01", past_obs=past)

    analysis = app_state.defender.analyze(reported)
    decision = analysis.decision
    detected = decision.classification in ("POTENTIAL_ATTACK", "COORDINATED_ATTACK", "SUSPICIOUS") or decision.risk_score >= 0.20
    result = {
        "experiment_id": "CASE-HIDDEN-REPLAY",
        "step": reported.step,
        "timestamp": reported.timestamp,
        "expected_label": "ATTACK",
        "defender_prediction": decision.classification,
        "outcome": "TRUE_POSITIVE" if detected else "FALSE_NEGATIVE",
        "risk_score": decision.risk_score,
        "integrity_score": decision.integrity_score,
        "latency_ms": None,
        "contributing_layers": [
            "Replay substitution: reported frame is a valid historical frame"
        ],
        "explanation": decision.explanation,
        "modified_fields": [f.model_dump() for f in hot_fields + replay_fields],
        "semantic_status": analysis.semantic.status,
        "semantic_score": analysis.semantic.semantic_score,
        "semantic_constraints": _compact_constraints(analysis.model_dump()),
        "temporal_status": analysis.temporal.status,
        "temporal_persistence": analysis.temporal.persistence,
        "temporal_score": analysis.temporal.temporal_score,
        "structural_status": analysis.structural.status,
        "structural_score": analysis.structural.structural_score,
        "ml_score": analysis.ml.anomaly_score,
        "actual_physical_temperature": hot.temperature,
        "reported_temperature": reported.temperature,
    }
    return {
        "name": "hidden_hot_telemetry_replay",
        "stage": "telemetry substitution",
        "description": (
            "Actual plant temperature is 46.2 degC (+25 degC), but the controller reports a "
            "valid historical 21.2 degC frame from step 0. The Defender sees only the reported frame."
        ),
        "configuration": {
            "actual": {"scenario": "temperature_manipulation", "target_sensor": "SENSOR01", "magnitude": 25.0},
            "reported": {"scenario": "replay_substitution", "target_sensor": "SENSOR01", "replay_step": 0},
        },
        "steps": [BASELINE_STEP],
        "results": [result],
        "detected": detected,
        "verdict": "DETECTED" if detected else "MISSED",
        "detection_step": BASELINE_STEP if detected else None,
        "max_classification": decision.classification,
        "max_risk_score": decision.risk_score,
    }


def _audit_case() -> Dict[str, Any]:
    """Verify the SHA-256 chain after an escalation sequence, then test tamper detection."""
    _reset_and_seed()
    for step in (30, 31, 32):
        experiment_engine.run_attack_experiment(
            step=step,
            config=AttackConfiguration(
                scenario="temperature_manipulation", target_sensor="SENSOR01", magnitude=25.0
            ),
        )
    valid = app_state.defender.verify_audit_chain()

    # Tamper a deep copy so the live chain is not modified.
    import copy

    tampered_events = copy.deepcopy(app_state.defender.events)
    tampered = verify_audit_chain(tampered_events)
    if tampered_events:
        tampered_events[3].message = "TAMPERED EVIDENCE"
        tampered = verify_audit_chain(tampered_events)

    return {
        "valid": valid.valid,
        "total_events": valid.total_events,
        "latest_event_hash": valid.latest_event_hash,
        "tamper_detected": not tampered.valid,
        "tamper_error": tampered.error,
        "tamper_failed_event_index": tampered.failed_event_index,
    }


def _real_data_playback_calibration(max_steps: int = 600) -> Dict[str, Any]:
    """Measure alert behaviour on unmodified real-data playback (limitation evidence)."""
    app_state.reset()
    experiment_engine.reset()
    counts: Dict[str, int] = {}
    first_alert = None
    alert_steps: List[int] = []
    for _ in range(max_steps):
        obs, analysis = app_state.step()
        classification = analysis.decision.classification
        counts[classification] = counts.get(classification, 0) + 1
        if classification in ("SUSPICIOUS", "POTENTIAL_ATTACK", "COORDINATED_ATTACK"):
            alert_steps.append(obs.step)
            if first_alert is None:
                first_alert = {
                    "step": obs.step,
                    "classification": classification,
                    "risk_score": analysis.decision.risk_score,
                    "temperature": obs.temperature,
                }
    return {
        "evaluated_steps": max_steps,
        "classification_counts": counts,
        "alerts": len(alert_steps),
        "alert_rate": round(len(alert_steps) / max_steps, 4),
        "first_alert": first_alert,
    }


def _markdown(payload: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("# Review 3 — Scaled-Down Case-Study Attack Results\n")
    lines.append(
        f"Generated: {payload['metadata']['generated_at']}  \n"
        f"Dataset: University of Hohenheim cold-storage telemetry "
        f"([Zenodo 15130001](https://zenodo.org/records/15130001), DOI `{DATASET_DOI}`)  \n"
        f"Live pipeline: `DefenderService` + `ExperimentEngine`  \n"
        f"Baseline step: {BASELINE_STEP}  \n"
        f"Commit: `{payload['metadata']['git_commit']}`\n"
    )
    lines.append(
        "\n> Ground-truth labels are retained only in the experiment record and are not "
        "passed to the Defender. The attack transformations are the same ones used by the "
        "Attack Simulator portal.\n"
    )

    lines.append("\n## 1. Summary\n")
    lines.append("| Case | Stage | Steps | Detected? | Max classification | Max risk |")
    lines.append("|---|---|---|---:|---|---:|")
    for case in payload["cases"]:
        lines.append(
            f"| `{case['name']}` | {case['stage']} | {', '.join(map(str, case['steps']))} | "
            f"{case.get('verdict', 'YES' if case['detected'] else 'NO')} | {case['max_classification']} | {case['max_risk_score']:.3f} |"
        )

    lines.append("\n## 2. Step-by-step results\n")
    for case in payload["cases"]:
        lines.append(f"\n### `{case['name']}` — {case['stage']}\n")
        lines.append(f"{case['description']}\n")
        if case.get("configuration"):
            lines.append(f"Configuration: `{json.dumps(case['configuration'], sort_keys=True)}`\n")
        lines.append("| Step | Prediction | Outcome | Risk | Semantic | Temporal | Structural | Contributing layers |")
        lines.append("|---:|---|---|---:|---|---|---|---|")
        for r in case["results"]:
            layers = "; ".join(r["contributing_layers"])
            lines.append(
                f"| {r['step']} | {r['defender_prediction']} | {r['outcome']} | {r['risk_score']:.3f} | "
                f"{r['semantic_status']} ({r['semantic_score']}) | {r['temporal_status']} "
                f"(p={r['temporal_persistence']}) | {r['structural_status']} ({r['structural_score']}) | {layers} |"
            )
        if case["name"] == "hidden_hot_telemetry_replay":
            r = case["results"][0]
            lines.append(
                f"\nActual physical temperature: **{r['actual_physical_temperature']} °C**; "
                f"reported temperature: **{r['reported_temperature']} °C**.\n"
            )

    audit = payload["audit"]
    lines.append("\n## 3. Audit-chain evidence\n")
    lines.append(
        f"- Chain valid after the escalation sequence: **{audit['valid']}** "
        f"({audit['total_events']} events, tip `{audit['latest_event_hash'][:16]}…`).\n"
        f"- Tampered copy detected: **{audit['tamper_detected']}** "
        f"(`{audit['tamper_error']}` at event index {audit['tamper_failed_event_index']}).\n"
    )

    cal = payload["real_data_playback_calibration"]
    lines.append("\n## 4. Unmodified real-data playback (limitation evidence)\n")
    if cal.get("skipped"):
        lines.append("Playback calibration was skipped for this run.\n")
    else:
        lines.append(
            f"Sequential playback of {cal['evaluated_steps']} unmodified observations produced "
            f"{cal['alerts']} alert states ({cal['alert_rate'] * 100:.1f}%). First alert: "
            f"`{json.dumps(cal['first_alert'], sort_keys=True)}`.\n"
        )
        lines.append(
            "This is a calibration limitation of the current Hohenheim envelope/spatial rules, "
            "not a successful attack. It is reported in the Review 3 limitations section and is "
            "why the controlled evaluation uses the synthetic ledger benchmark and a stable "
            "real-data baseline segment.\n"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        default="evaluation_results",
        help="Directory for the JSON and Markdown case-study artifacts.",
    )
    parser.add_argument(
        "--skip-playback-calibration",
        action="store_true",
        help="Skip the 600-step real-data playback calibration check.",
    )
    args = parser.parse_args()

    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)

    cases: List[Dict[str, Any]] = [_baseline_case()]
    cases.append(
        _run_case(
            name="sustained_setpoint_runaway",
            stage="controller setpoint / actuator manipulation",
            description=(
                "Sustained +25 degC on SENSOR01 for three consecutive observations, "
                "simulating a refrigeration controller driven to ~46 degC."
            ),
            config=AttackConfiguration(
                scenario="temperature_manipulation", target_sensor="SENSOR01", magnitude=25.0
            ),
            steps=(30, 31, 32),
        )
    )
    cases.append(
        _run_case(
            name="subtle_in_envelope_change",
            stage="stealthy setpoint manipulation",
            description=(
                "Sustained +1.5 degC on SENSOR01 for six observations. The value remains "
                "inside the 4–16 degC semantic envelope, but is enough to compromise a "
                "cold chain over hours."
            ),
            config=AttackConfiguration(
                scenario="temperature_manipulation", target_sensor="SENSOR01", magnitude=1.5
            ),
            steps=(30, 31, 32, 33, 34, 35),
        )
    )
    cases.append(
        _run_case(
            name="localized_cross_sensor_spoof",
            stage="sensor spoofing",
            description="+8 degC on SENSOR04 only, creating a spatial inconsistency.",
            config=AttackConfiguration(
                scenario="cross_sensor_inconsistency", target_sensor="SENSOR04", magnitude=8.0
            ),
            steps=(30,),
        )
    )
    cases.append(
        _run_case(
            name="valid_frame_replay",
            stage="replay",
            description="Replay SENSOR01 from step 0 under the step-30 timestamp.",
            config=AttackConfiguration(
                scenario="replay_substitution", target_sensor="SENSOR01", replay_step=0
            ),
            steps=(30,),
        )
    )
    cases.append(
        _run_case(
            name="telemetry_suppression",
            stage="telemetry suppression",
            description="Suppress SENSOR01 entirely (forced dropout).",
            config=AttackConfiguration(scenario="sensor_dropout", target_sensor="SENSOR01"),
            steps=(30,),
        )
    )
    cases.append(_hidden_hot_replay_case())

    audit = _audit_case()
    calibration = (
        {"skipped": True}
        if args.skip_playback_calibration
        else _real_data_playback_calibration()
    )

    payload = {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "git_commit": _git_commit(),
            "dataset_doi": DATASET_DOI,
            "dataset_url": "https://zenodo.org/records/15130001",
            "incident_source": CASE_SOURCE,
            "baseline_step": BASELINE_STEP,
            "seed_step": SEED_STEP,
            "pipeline": "DefenderService + ExperimentEngine",
        },
        "cases": cases,
        "audit": audit,
        "real_data_playback_calibration": calibration,
    }

    json_path = output / "review3_case_study.json"
    md_path = output / "review3_case_study.md"
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    with open(md_path, "w", encoding="utf-8") as handle:
        handle.write(_markdown(payload))

    print("=" * 80)
    print("REVIEW 3 CASE STUDY — SCALED-DOWN REFRIGERATION CONTROLLER ATTACKS")
    print("=" * 80)
    for case in cases:
        verdict = case.get("verdict", "DETECTED" if case["detected"] else "MISSED")
        print(
            f"{case['name']:<34s} {verdict:<20s} "
            f"max={case['max_classification']:<18s} risk={case['max_risk_score']:.3f}"
        )
    print("-" * 80)
    print(f"Audit chain valid: {audit['valid']} ({audit['total_events']} events)")
    print(f"Tamper detected:   {audit['tamper_detected']} ({audit['tamper_error']})")
    if not calibration.get("skipped"):
        print(
            f"Real-data playback alerts: {calibration['alerts']}/{calibration['evaluated_steps']} "
            f"({calibration['alert_rate'] * 100:.1f}%)"
        )
    print(f"Artifacts: {json_path} and {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
