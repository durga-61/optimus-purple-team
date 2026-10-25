"""Reproducible advanced OPTIMUS experiments.

Runs adaptive fusion, dynamic invariant mining, independent One-Class SVM/PCA
baselines, the evasion frontier, an audit-lifecycle verification, and exports
split manifests plus SHA-256 checksums for every artifact.

All labels used for weight/invariant learning come from the trusted temporal
validation split.  The held-out test split is touched only for final scoring.
"""

from collections import Counter, defaultdict
from copy import deepcopy
import csv
from datetime import datetime, timezone
import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

from app.config import settings
from app.defender.adaptive_fusion import (
    DEFAULT_FUSION_WEIGHTS,
    adapt_weights,
    calibrate_threshold,
    collect_layer_outputs,
    evaluate_decision_rows,
)
from app.defender.audit import verify_audit_chain
from app.defender.decision import JointDecisionEngine
from app.defender.hardening import HardeningEngine, HardeningProposal
from app.defender.invariant_miner import InvariantMiner
from app.defender.ml_detector import MLDetector
from app.defender.semantic import SemanticEngine
from app.defender.service import DefenderService
from app.defender.structural import StructuralEngine
from app.defender.temporal import TemporalEngine
from app.evaluation.baselines import (
    evaluate_detector,
    fit_baseline_detectors,
)
from app.evaluation.dataset import (
    EvaluationRecord,
    create_temporal_splits,
    generate_attack_dataset,
    generate_normal_dataset,
)
from app.evaluation.evasion_frontier import (
    BaselinePredictor,
    PipelinePredictor,
    compute_frontier,
    export_evasion_frontier,
    generate_frontier_records,
    summarise_frontier,
)
from app.simulator.models import WarehouseObservation

logger = logging.getLogger("evaluation.advanced")


def build_datasets(
    seed: int = 42,
    num_normal: int = 12000,
    num_attack_per_class: int = 2000,
):
    """Generate the canonical deterministic dataset and temporal splits."""
    normal_records = generate_normal_dataset(num_samples=num_normal, seed=seed)
    attack_records = generate_attack_dataset(num_samples_per_class=num_attack_per_class, seed=seed)
    return create_temporal_splits(
        normal_records=normal_records,
        attack_records=attack_records,
        train_ratio=0.60,
        val_ratio=0.20,
        test_ratio=0.20,
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_jsonl(records: Sequence[EvaluationRecord], path: Path) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        for record in records:
            handle.write(
                json.dumps(record.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
                + "\n"
            )


def export_dataset_splits(
    splits,
    output_dir: str | Path,
    seed: int,
    num_normal: int,
    num_attack_per_class: int,
) -> Dict[str, Any]:
    """Export exact split files and an immutable manifest of their SHA-256 digests."""
    output = Path(output_dir)
    dataset_dir = output / "datasets"
    dataset_dir.mkdir(parents=True, exist_ok=True)

    manifest: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generation": {
            "seed": seed,
            "num_normal": num_normal,
            "num_attack_per_class": num_attack_per_class,
            "attack_classes": sorted({r.attack_type for r in splits.test if r.ground_truth_label == 1}),
            "train_ratio": 0.60,
            "val_ratio": 0.20,
            "test_ratio": 0.20,
            "timestamp_policy": "deterministic dataset epoch (2026-01-01 UTC + step seconds)",
        },
        "splits": {},
    }

    for split_name in ("train", "val", "test"):
        records = getattr(splits, split_name)
        path = dataset_dir / f"{split_name}.jsonl"
        _write_jsonl(records, path)
        attack_counts = Counter(
            record.attack_type or "normal" for record in records if record.ground_truth_label == 1
        )
        manifest["splits"][split_name] = {
            "path": path.relative_to(output).as_posix(),
            "sha256": _sha256_file(path),
            "records": len(records),
            "normal_records": sum(1 for record in records if record.ground_truth_label == 0),
            "attack_records": sum(1 for record in records if record.ground_truth_label == 1),
            "attack_class_counts": dict(sorted(attack_counts.items())),
        }

    manifest_path = output / "dataset_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
    logger.info("Exported dataset splits and manifest to %s", dataset_dir)
    return manifest


def evaluate_pipeline(
    records: Sequence[EvaluationRecord],
    ml_detector: Any,
    weights: Optional[Dict[str, float]] = None,
    active_invariants: Optional[Sequence[Any]] = None,
) -> Dict[str, Any]:
    """Run a complete pipeline configuration over records and return metrics."""
    import time

    semantic = SemanticEngine()
    for invariant in active_invariants or []:
        semantic.add_invariant(invariant)
    temporal = TemporalEngine()
    structural = StructuralEngine()
    decision = JointDecisionEngine()
    if weights:
        decision.update_weights(weights)

    y_true: List[int] = []
    y_pred: List[int] = []
    class_true: Dict[str, List[int]] = defaultdict(list)
    class_pred: Dict[str, List[int]] = defaultdict(list)
    risk_scores: List[float] = []
    latencies_ms: List[float] = []
    classification_counts: Counter = Counter()

    previous = None
    history: List[WarehouseObservation] = []
    for record in records:
        observation = record.get_inference_observation()
        started = time.perf_counter()
        ml = ml_detector.analyze(observation)
        semantic_result = semantic.analyze(observation, previous_obs=previous, history=history)
        structural_result = structural.analyze(semantic_result=semantic_result, ml_result=ml)
        temporal_result = temporal.update(
            step=observation.step,
            semantic_result=semantic_result,
            ml_result=ml,
            structural_result=structural_result,
        )
        decision_result = decision.decide(
            ml=ml,
            semantic=semantic_result,
            temporal=temporal_result,
            structural=structural_result,
        )
        latencies_ms.append((time.perf_counter() - started) * 1000.0)

        predicted = int(
            decision_result.classification in ("POTENTIAL_ATTACK", "COORDINATED_ATTACK")
        )
        y_true.append(int(record.ground_truth_label))
        y_pred.append(predicted)
        risk_scores.append(float(decision_result.risk_score))
        classification_counts[decision_result.classification] += 1
        if record.ground_truth_label == 1:
            attack_type = record.attack_type or "unknown"
            class_true[attack_type].append(1)
            class_pred[attack_type].append(predicted)

        previous = observation
        history.append(observation)
        if len(history) > settings.HISTORY_BUFFER_SIZE:
            history.pop(0)

    tp = sum(1 for truth, pred in zip(y_true, y_pred) if truth == 1 and pred == 1)
    fp = sum(1 for truth, pred in zip(y_true, y_pred) if truth == 0 and pred == 1)
    tn = sum(1 for truth, pred in zip(y_true, y_pred) if truth == 0 and pred == 0)
    fn = sum(1 for truth, pred in zip(y_true, y_pred) if truth == 1 and pred == 0)
    total = len(y_true)
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    latency = np.asarray(latencies_ms, dtype=float)

    per_class_recall = {}
    for attack_type, truths in class_true.items():
        predictions = class_pred.get(attack_type, [])
        per_class_recall[attack_type] = (
            sum(1 for prediction in predictions if prediction == 1) / len(truths)
            if truths
            else 0.0
        )

    return {
        "total_samples": total,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "detection_rate": round(recall, 4),
        "recall": round(recall, 4),
        "precision": round(precision, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "accuracy": round((tp + tn) / total, 4) if total else 0.0,
        "evasion_rate": round(1.0 - recall, 4),
        "per_class_recall": {key: round(value, 4) for key, value in sorted(per_class_recall.items())},
        "per_class_evasion": {
            key: round(1.0 - value, 4) for key, value in sorted(per_class_recall.items())
        },
        "mean_risk_score": round(float(np.mean(risk_scores)), 4) if risk_scores else 0.0,
        "classification_counts": dict(sorted(classification_counts.items())),
        "latency_ms": {
            "mean": round(float(np.mean(latency)), 3),
            "median": round(float(np.median(latency)), 3),
            "p95": round(float(np.percentile(latency, 95)), 3),
            "p99": round(float(np.percentile(latency, 99)), 3),
        },
    }


def _decision_scores(rows: Sequence[Dict[str, Any]], engine: JointDecisionEngine) -> np.ndarray:
    return np.asarray(
        [
            engine.decide(
                ml=row["ml"],
                semantic=row["semantic"],
                temporal=row["temporal"],
                structural=row["structural"],
            ).risk_score
            for row in rows
        ],
        dtype=float,
    )


def run_adaptive_fusion_experiment(
    splits,
    ml_detector: Any,
    output_dir: str | Path,
) -> Dict[str, Any]:
    """Learn bounded weights on validation data and compare static vs adaptive."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    validation_rows = collect_layer_outputs(splits.val, ml_detector)
    result = adapt_weights(
        validation_rows,
        max_fpr=settings.ADAPTIVE_FUSION_MAX_FPR,
        seed=settings.ADAPTIVE_FUSION_SEED,
    )
    labels = np.asarray([row["label"] for row in validation_rows], dtype=int)

    static_engine = JointDecisionEngine()
    adaptive_engine = JointDecisionEngine()
    adaptive_engine.update_weights(result.weights)

    static_threshold = calibrate_threshold(
        _decision_scores(validation_rows, static_engine),
        labels,
        max_fpr=settings.ADAPTIVE_FUSION_MAX_FPR,
    )
    adaptive_threshold = calibrate_threshold(
        _decision_scores(validation_rows, adaptive_engine),
        labels,
        max_fpr=settings.ADAPTIVE_FUSION_MAX_FPR,
    )

    test_rows = collect_layer_outputs(splits.test, ml_detector)
    comparisons = {
        "optimus_static_rule": evaluate_decision_rows(test_rows, static_engine, mode="rule"),
        "optimus_adaptive_rule": evaluate_decision_rows(test_rows, adaptive_engine, mode="rule"),
        "optimus_static_risk": evaluate_decision_rows(
            test_rows,
            static_engine,
            mode="risk",
            threshold=static_threshold.threshold,
        ),
        "optimus_adaptive_risk": evaluate_decision_rows(
            test_rows,
            adaptive_engine,
            mode="risk",
            threshold=adaptive_threshold.threshold,
        ),
    }

    payload = {
        "metadata": {
            "test_samples": len(splits.test),
            "validation_samples": len(splits.val),
            "max_fpr": settings.ADAPTIVE_FUSION_MAX_FPR,
            "static_weights": DEFAULT_FUSION_WEIGHTS,
            "static_threshold": static_threshold.model_dump(),
            "adaptive_threshold": adaptive_threshold.model_dump(),
            "adaptive_result": result.model_dump(),
            "trusted_label_source": "temporal validation split (splits.val)",
        },
        "comparisons": comparisons,
    }
    json_path = output / "adaptive_fusion_comparison.json"
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)

    csv_path = output / "adaptive_fusion_comparison.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "configuration",
                "criterion",
                "threshold",
                "precision",
                "recall",
                "f1",
                "false_positive_rate",
                "accuracy",
                "evasion_rate",
                "mean_risk_score",
            ]
        )
        for name, metrics in comparisons.items():
            writer.writerow(
                [
                    name,
                    metrics["mode"],
                    metrics["threshold"],
                    metrics["precision"],
                    metrics["recall"],
                    metrics["f1"],
                    metrics["false_positive_rate"],
                    metrics["accuracy"],
                    metrics["evasion_rate"],
                    metrics["mean_risk_score"],
                ]
            )
    logger.info("Adaptive fusion experiment complete: %s", result.weights)
    return payload


def run_invariant_mining_experiment(
    splits,
    ml_detector: Any,
    adaptive_weights: Optional[Dict[str, float]],
    output_dir: str | Path,
) -> Dict[str, Any]:
    """Mine/validate invariants, then measure their independent effect on test data."""
    output = Path(output_dir)
    mining_service = DefenderService(ml_detector=ml_detector)
    miner = InvariantMiner(service=mining_service)

    candidates = miner.discover([r.get_inference_observation() for r in splits.train])
    val_normal = [r for r in splits.val if r.ground_truth_label == 0]
    val_attack = [r for r in splits.val if r.ground_truth_label == 1]
    miner.validate(candidates, normal_records=val_normal, attack_records=val_attack)

    validated = miner.get_candidates("VALIDATED")
    scratch_engine = SemanticEngine()
    active_invariants = (
        miner.activate(semantic_engine=scratch_engine, operator_approved=True)
        if validated
        else []
    )

    base_metrics = evaluate_pipeline(splits.test, ml_detector)
    invariant_metrics = evaluate_pipeline(splits.test, ml_detector, active_invariants=active_invariants)
    combined_metrics = evaluate_pipeline(
        splits.test,
        ml_detector,
        weights=adaptive_weights,
        active_invariants=active_invariants,
    )
    chain = mining_service.verify_audit_chain()

    payload = {
        "metadata": {
            "discovered": len(miner.candidates),
            "validated": len(validated),
            "rejected": len(miner.get_candidates("REJECTED")),
            "active": len(active_invariants),
            "activation_required_operator_approval": True,
            "audit_chain_valid": chain.valid,
            "audit_events": chain.total_events,
        },
        "candidates": [candidate.model_dump() for candidate in miner.candidates.values()],
        "comparisons": {
            "optimus_static": base_metrics,
            "optimus_invariants": invariant_metrics,
            "optimus_combined": combined_metrics,
        },
    }

    json_path = output / "invariant_mining_experiment.json"
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)

    csv_path = output / "invariant_candidates.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "candidate_id",
                "name",
                "family",
                "kind",
                "tolerance",
                "status",
                "validation_coverage",
                "false_positive_rate",
                "attack_detection_rate",
                "stability_gap",
                "duplicate_of",
                "rejection_reason",
                "per_class_detection",
            ]
        )
        for candidate in miner.candidates.values():
            writer.writerow(
                [
                    candidate.candidate_id,
                    candidate.name,
                    candidate.family,
                    candidate.kind,
                    candidate.tolerance,
                    candidate.status,
                    candidate.validation_coverage,
                    candidate.false_positive_rate,
                    candidate.attack_detection_rate,
                    candidate.stability_gap,
                    candidate.duplicate_of or "",
                    candidate.rejection_reason or "",
                    json.dumps(candidate.per_class_detection, sort_keys=True),
                ]
            )

    comparison_csv = output / "invariant_mining_comparison.csv"
    with open(comparison_csv, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "configuration",
                "precision",
                "recall",
                "f1",
                "false_positive_rate",
                "accuracy",
                "evasion_rate",
                "mean_risk_score",
            ]
        )
        for name, metrics in payload["comparisons"].items():
            writer.writerow(
                [
                    name,
                    metrics["precision"],
                    metrics["recall"],
                    metrics["f1"],
                    metrics["false_positive_rate"],
                    metrics["accuracy"],
                    metrics["evasion_rate"],
                    metrics["mean_risk_score"],
                ]
            )
    logger.info(
        "Invariant mining complete: %d discovered, %d validated, %d active.",
        len(miner.candidates),
        len(validated),
        len(active_invariants),
    )
    return {
        "payload": payload,
        "active_invariants": active_invariants,
        "miner": miner,
        "base_metrics": base_metrics,
    }


def run_baseline_experiment(
    splits,
    optimus_metrics: Dict[str, Any],
    output_dir: str | Path,
) -> Dict[str, Any]:
    """Fit One-Class SVM and PCA, calibrate on validation, evaluate held-out test."""
    output = Path(output_dir)
    detectors = fit_baseline_detectors(
        train_records=splits.train,
        validation_records=splits.val,
        max_fpr=settings.ADAPTIVE_FUSION_MAX_FPR,
    )
    results = {
        "optimus_static": optimus_metrics,
        "one_class_svm": evaluate_detector(detectors["one_class_svm"], splits.test),
        "pca": evaluate_detector(detectors["pca"], splits.test),
    }
    payload = {
        "metadata": {
            "train_samples": len(splits.train),
            "validation_samples": len(splits.val),
            "test_samples": len(splits.test),
            "features": [
                "temperature",
                "humidity",
                "inventory",
                "free_capacity",
                "inbound",
                "outbound",
                "occupancy",
            ],
            "threshold_policy": (
                "max F1 on validation subject to "
                f"FPR <= {settings.ADAPTIVE_FUSION_MAX_FPR}"
            ),
            "one_class_svm": {"nu": 0.03, "kernel": "rbf", "gamma": "scale", "scaled": True},
            "pca": {"n_components": 0.95, "score": "standardized reconstruction MSE"},
        },
        "results": results,
    }
    json_path = output / "baseline_comparison.json"
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)

    csv_path = output / "baseline_comparison.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "detector",
                "precision",
                "recall",
                "f1",
                "false_positive_rate",
                "accuracy",
                "evasion_rate",
                "threshold",
                "per_class_recall",
            ]
        )
        for name, metrics in results.items():
            writer.writerow(
                [
                    name,
                    metrics["precision"],
                    metrics["recall"],
                    metrics["f1"],
                    metrics["false_positive_rate"],
                    metrics["accuracy"],
                    metrics["evasion_rate"],
                    metrics.get("threshold"),
                    json.dumps(metrics.get("per_class_recall", {}), sort_keys=True),
                ]
            )
    logger.info("Baseline experiment complete.")
    return {"payload": payload, "detectors": detectors, "results": results}


def run_evasion_frontier_experiment(
    ml_detector: Any,
    adaptive_weights: Optional[Dict[str, float]],
    active_invariants: Sequence[Any],
    detectors: Dict[str, Any],
    output_dir: str | Path,
    seed: int = 42,
    episodes_per_class: int = 8,
    episode_length: int = 8,
) -> Dict[str, Any]:
    """Generate scaled attacks and measure evasion for every configuration."""
    records = generate_frontier_records(
        seed=seed,
        episodes_per_class=episodes_per_class,
        episode_length=episode_length,
    )
    configs = {
        "optimus_static": PipelinePredictor(ml_detector),
        "optimus_adaptive": PipelinePredictor(ml_detector, weights=adaptive_weights),
        "optimus_invariants": PipelinePredictor(
            ml_detector, active_invariants=active_invariants
        ),
        "optimus_combined": PipelinePredictor(
            ml_detector,
            weights=adaptive_weights,
            active_invariants=active_invariants,
        ),
        "one_class_svm": BaselinePredictor(detectors["one_class_svm"]),
        "pca": BaselinePredictor(detectors["pca"]),
    }
    frontier = compute_frontier(records, configs)
    frontier["summary"] = summarise_frontier(frontier)
    frontier["metadata"] = {
        "seed": seed,
        "episodes_per_class": episodes_per_class,
        "episode_length": episode_length,
        "strengths": sorted({float(r.metadata["strength"]) for r in records}),
        "records": len(records),
    }
    exported = export_evasion_frontier(frontier, output_dir)
    frontier["exported_files"] = exported
    logger.info("Evasion frontier experiment complete: %s", frontier["summary"])
    return frontier


def _mock_record(
    step: int,
    inventory: float,
    free_capacity: float,
    is_attack: bool,
) -> EvaluationRecord:
    observation = WarehouseObservation(
        step=step,
        timestamp=f"2026-10-20T10:{step % 60:02d}:00Z",
        warehouse="W01",
        temperature=4.2,
        humidity=71.0,
        inventory=round(inventory, 2),
        free_capacity=round(free_capacity, 2),
        capacity=50.0,
        occupancy=round((inventory / 50.0) * 100.0, 1),
        inbound=1.0,
        outbound=1.0,
    )
    return EvaluationRecord(
        record_id=f"LIFECYCLE-{step:04d}",
        observation=observation,
        ground_truth_label=1 if is_attack else 0,
        attack_type="coordinated_weak" if is_attack else "normal",
        episode_id="EP-LIFECYCLE",
        step_in_episode=step,
    )


def run_audit_lifecycle_check(output_dir: str | Path) -> Dict[str, Any]:
    """Exercise miss -> proposal -> rejection/approval -> activation -> rollback."""
    output = Path(output_dir)
    service = DefenderService(ml_detector=MLDetector(random_state=42))
    engine: HardeningEngine = service.hardening_engine

    observation = WarehouseObservation(
        step=1,
        timestamp="2026-10-20T12:00:00Z",
        warehouse="W01",
        temperature=4.2,
        humidity=71.0,
        inventory=40.5,
        free_capacity=9.0,
        capacity=50.0,
        occupancy=81.0,
        inbound=1.0,
        outbound=1.0,
    )
    analysis = service.analyze(observation)
    miss = engine.record_miss(
        observation=observation,
        analysis=analysis,
        attack_type="coordinated_weak",
        target="sensors_and_inventory",
        value=-1.5,
    )
    proposal = engine.generate_proposal(miss)
    assert proposal is not None

    validation_records = [
        _mock_record(i, inventory=42.0, free_capacity=8.0, is_attack=False) for i in range(20)
    ] + [
        _mock_record(i, inventory=40.5, free_capacity=9.0, is_attack=True) for i in range(20, 40)
    ]
    validation = engine.validate_proposal(
        proposal=proposal,
        validation_records=validation_records,
        max_allowed_fpr=0.001,
    )

    unauthorized_blocked = False
    try:
        engine.activate_proposal(proposal.proposal_id)
    except PermissionError:
        unauthorized_blocked = True

    if validation.verdict == "PASSED":
        engine.approve_proposal(proposal.proposal_id, operator_name="LeadSecurityOfficer")
        engine.activate_proposal(proposal.proposal_id)

    # Rejection logging: a no-op proposal must not improve the objective.
    rejected = HardeningProposal(
        trigger_miss_id=miss.miss_id,
        adjustment_type="TOLERANCE_TIGHTENING",
        target_parameter="c1_tolerance",
        current_value=engine.current_parameters["c1_tolerance"],
        proposed_value=engine.current_parameters["c1_tolerance"],
        parameter_bounds=(0.10, 0.50),
        rationale="Lifecycle no-op rejection check",
    )
    engine.proposals[rejected.proposal_id] = rejected
    rejected_validation = engine.validate_proposal(
        proposal=rejected,
        validation_records=validation_records,
        max_allowed_fpr=0.001,
    )

    rolled_back = engine.rollback(proposal.proposal_id if validation.verdict == "PASSED" else None)
    chain = service.verify_audit_chain()

    tampered = deepcopy(service.events)
    if tampered:
        tampered[0].message = "TAMPERED LIFECYCLE EVENT"
    tampered_result = verify_audit_chain(tampered)

    event_types = Counter(event.event_type for event in service.events)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "miss_id": miss.miss_id,
        "proposal_id": proposal.proposal_id,
        "validation_verdict": validation.verdict,
        "unauthorized_activation_blocked": unauthorized_blocked,
        "rejected_proposal_verdict": rejected_validation.verdict,
        "rejection_logged": event_types.get("HARDENING_PROPOSAL_REJECTED", 0) > 0,
        "rollback": rolled_back,
        "baseline_parameters": engine.baseline_config,
        "active_parameters_after_rollback": engine.current_parameters,
        "audit_chain_valid": chain.valid,
        "audit_events": chain.total_events,
        "event_types": dict(sorted(event_types.items())),
        "tamper_detected": not tampered_result.valid,
        "tamper_error": tampered_result.error,
        "lifecycle_complete": all(
            event_types.get(event_type, 0) > 0
            for event_type in (
                "HARDENING_MISS_RECORDED",
                "HARDENING_PROPOSAL_GENERATED",
                "HARDENING_PROPOSAL_VALIDATED",
                "HARDENING_PROPOSAL_REJECTED",
                "HARDENING_PROPOSAL_APPROVED",
                "HARDENING_PROPOSAL_ACTIVATED",
                "HARDENING_ROLLED_BACK",
            )
        ),
    }
    path = output / "audit_lifecycle_verification.json"
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    logger.info("Audit lifecycle verification complete: valid=%s", chain.valid)
    return payload


def write_artifact_checksums(output_dir: str | Path) -> Dict[str, str]:
    """Hash every exported artifact except the checksum file itself."""
    output = Path(output_dir)
    checksums: Dict[str, str] = {}
    for path in sorted(output.rglob("*")):
        if not path.is_file() or path.name == "artifacts_checksums.json":
            continue
        checksums[path.relative_to(output).as_posix()] = _sha256_file(path)
    path = output / "artifacts_checksums.json"
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(checksums, handle, indent=2, sort_keys=True)
    return checksums


def write_results_markdown(
    output_dir: str | Path,
    manifest: Dict[str, Any],
    adaptive: Dict[str, Any],
    invariant: Dict[str, Any],
    baselines: Dict[str, Any],
    frontier: Dict[str, Any],
    audit: Dict[str, Any],
) -> str:
    """Write a concise, review-ready summary of all advanced experiments."""
    output = Path(output_dir)
    lines = [
        "# OPTIMUS Advanced Experiment Results",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Dataset provenance",
        "",
        f"- Seed: {manifest['generation']['seed']}",
        f"- Normal generated: {manifest['generation']['num_normal']}",
        f"- Attack generated per class: {manifest['generation']['num_attack_per_class']}",
        "",
        "| Split | Records | Normal | Attack | SHA-256 |",
        "|---|---:|---:|---:|---|",
    ]
    for split_name, info in manifest["splits"].items():
        lines.append(
            f"| {split_name} | {info['records']} | {info['normal_records']} | "
            f"{info['attack_records']} | `{info['sha256'][:16]}…` |"
        )

    lines += [
        "",
        "## Adaptive fusion",
        "",
        f"- Static weights: `{adaptive['metadata']['static_weights']}`",
        f"- Adapted weights: `{adaptive['metadata']['adaptive_result']['weights']}`",
        f"- Adopted: {adaptive['metadata']['adaptive_result']['adopted']}",
        "",
        "| Configuration | Precision | Recall | F1 | FPR | Evasion |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for name, metrics in adaptive["comparisons"].items():
        lines.append(
            f"| {name} | {metrics['precision']:.4f} | {metrics['recall']:.4f} | "
            f"{metrics['f1']:.4f} | {metrics['false_positive_rate']:.4f} | "
            f"{metrics['evasion_rate']:.4f} |"
        )

    payload = invariant["payload"]
    lines += [
        "",
        "## Dynamic invariant mining",
        "",
        f"- Discovered: {payload['metadata']['discovered']}",
        f"- Validated: {payload['metadata']['validated']}",
        f"- Rejected: {payload['metadata']['rejected']}",
        f"- Active: {payload['metadata']['active']}",
        f"- Mining audit chain valid: {payload['metadata']['audit_chain_valid']}",
        "",
        "| Configuration | Precision | Recall | F1 | FPR |",
        "|---|---:|---:|---:|---:|",
    ]
    for name, metrics in payload["comparisons"].items():
        lines.append(
            f"| {name} | {metrics['precision']:.4f} | {metrics['recall']:.4f} | "
            f"{metrics['f1']:.4f} | {metrics['false_positive_rate']:.4f} |"
        )

    lines += [
        "",
        "## Independent baselines",
        "",
        "| Detector | Precision | Recall | F1 | FPR | Evasion |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for name, metrics in baselines["results"].items():
        lines.append(
            f"| {name} | {metrics['precision']:.4f} | {metrics['recall']:.4f} | "
            f"{metrics['f1']:.4f} | {metrics['false_positive_rate']:.4f} | "
            f"{metrics['evasion_rate']:.4f} |"
        )

    lines += [
        "",
        "## Evasion frontier",
        "",
        "| Configuration | Mean evasion | Evasion at full strength |",
        "|---|---:|---:|",
    ]
    for name, summary in frontier["summary"].items():
        lines.append(
            f"| {name} | {summary['mean_evasion_across_strengths']:.4f} | "
            f"{summary['evasion_at_full_strength']:.4f} |"
        )

    lines += [
        "",
        "## Audit lifecycle",
        "",
        f"- Chain valid: {audit['audit_chain_valid']}",
        f"- Events: {audit['audit_events']}",
        f"- Unauthorized activation blocked: {audit['unauthorized_activation_blocked']}",
        f"- Rejected proposal logged: {audit['rejection_logged']}",
        f"- Tamper detected: {audit['tamper_detected']}",
        f"- Full lifecycle present: {audit['lifecycle_complete']}",
        "",
        "## Limitations",
        "",
        "- Evasion frontier thresholds are calibrated on the validation split; test/"
        "frontier data is never used for tuning.",
        "- The audit chain is in-memory and does not survive process restart; durable "
        "tamper-evidence requires append-only external storage.",
        "- Mined invariants are statistical hypotheses validated on independent normal/"
        "attack data. They still require domain review before production use.",
        "- Replay attacks with stationary inventory and in-envelope drift remain a "
        "passive-monitoring limitation requiring cryptographic freshness.",
    ]
    path = output / "ADVANCED_RESULTS.md"
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    return str(path)


def run_all_experiments(
    seed: int = 42,
    num_normal: int = 12000,
    num_attack_per_class: int = 2000,
    output_dir: str | Path = "evaluation_results",
    episodes_per_class: int = 8,
    episode_length: int = 8,
) -> Dict[str, Any]:
    """Run every advanced experiment in dependency order and export artifacts."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("OPTIMUS ADVANCED EXPERIMENTS")
    print("=" * 80)
    print(f"Seed: {seed} | Normal: {num_normal} | Attacks/class: {num_attack_per_class}")
    print(f"Output: {output}")

    print("\n[1/7] Generating datasets and temporal splits...")
    splits = build_datasets(seed=seed, num_normal=num_normal, num_attack_per_class=num_attack_per_class)
    manifest = export_dataset_splits(
        splits, output, seed=seed, num_normal=num_normal, num_attack_per_class=num_attack_per_class
    )
    print(
        f"  train={len(splits.train)} val={len(splits.val)} test={len(splits.test)} "
        f"(test attacks={sum(1 for r in splits.test if r.ground_truth_label == 1)})"
    )

    print("\n[2/7] Fitting ML detector on training normals only...")
    ml_detector = MLDetector(random_state=seed)
    ml_detector.fit([r.get_inference_observation() for r in splits.train])

    print("\n[3/7] Adaptive fusion weights (trusted validation labels only)...")
    adaptive = run_adaptive_fusion_experiment(splits, ml_detector, output)
    print(f"  adapted weights: {adaptive['metadata']['adaptive_result']['weights']}")

    print("\n[4/7] Dynamic invariant mining and validation...")
    invariant = run_invariant_mining_experiment(
        splits,
        ml_detector,
        adaptive["metadata"]["adaptive_result"]["weights"],
        output,
    )
    print(
        f"  discovered={invariant['payload']['metadata']['discovered']} "
        f"validated={invariant['payload']['metadata']['validated']} "
        f"active={invariant['payload']['metadata']['active']}"
    )

    print("\n[5/7] Independent One-Class SVM and PCA baselines...")
    baselines = run_baseline_experiment(
        splits,
        adaptive["comparisons"]["optimus_static_rule"],
        output,
    )

    print("\n[6/7] Evasion frontier across scaled attack magnitudes...")
    frontier = run_evasion_frontier_experiment(
        ml_detector=ml_detector,
        adaptive_weights=adaptive["metadata"]["adaptive_result"]["weights"],
        active_invariants=invariant["active_invariants"],
        detectors=baselines["detectors"],
        output_dir=output,
        seed=seed,
        episodes_per_class=episodes_per_class,
        episode_length=episode_length,
    )

    print("\n[7/7] Audit-chain lifecycle and tamper verification...")
    audit = run_audit_lifecycle_check(output)

    markdown = write_results_markdown(output, manifest, adaptive, invariant, baselines, frontier, audit)
    checksums = write_artifact_checksums(output)

    print("\n" + "=" * 80)
    print("ADVANCED EXPERIMENTS COMPLETE")
    print("=" * 80)
    print(f"Summary: {markdown}")
    print(f"Checksums: {output / 'artifacts_checksums.json'} ({len(checksums)} files)")
    return {
        "manifest": manifest,
        "adaptive": adaptive,
        "invariant": invariant["payload"],
        "baselines": baselines["payload"],
        "frontier": frontier,
        "audit": audit,
        "checksums": checksums,
    }
