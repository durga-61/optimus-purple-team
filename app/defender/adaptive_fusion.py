"""Trusted-label adaptive fusion of the four OPTIMUS detection layers.

The static fusion weights only shape the composite risk score.  This module
learns a bounded, normalized weight vector from independently validated
normal/attack labels and applies it through ``JointDecisionEngine.update_weights``.

Security boundary:
- Only trusted validation labels may be passed here.  Never feed attacker
  claims, unverified alerts, or live packet feedback into ``adapt_weights``.
- Weights remain non-negative, sum to 1.0, and stay inside ``FUSION_WEIGHT_BOUNDS``.
- The decision rules and per-layer detectors are unchanged; only their fusion
  contribution is re-weighted.
"""

from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np
from pydantic import BaseModel, Field

from app.config import settings
from app.defender.decision import (
    FUSION_WEIGHT_BOUNDS,
    FUSION_WEIGHT_KEYS,
    JointDecisionEngine,
    validate_fusion_weights,
)

DEFAULT_FUSION_WEIGHTS: Dict[str, float] = {
    "semantic": settings.DECISION_WEIGHT_SEMANTIC,
    "temporal": settings.DECISION_WEIGHT_TEMPORAL,
    "structural": settings.DECISION_WEIGHT_STRUCTURAL,
    "ml": settings.DECISION_WEIGHT_ML,
}


class ThresholdCalibration(BaseModel):
    """Best F1 threshold under a hard false-positive-rate ceiling."""

    threshold: float
    f1: float
    recall: float
    precision: float
    false_positive_rate: float


class AdaptiveFusionResult(BaseModel):
    """Outcome of a trusted-label fusion-weight search."""

    weights: Dict[str, float]
    threshold: float
    validation_f1: float
    validation_recall: float
    validation_precision: float
    validation_fpr: float
    baseline_weights: Dict[str, float]
    baseline_threshold: float
    baseline_f1: float
    baseline_recall: float
    baseline_precision: float
    baseline_fpr: float
    adopted: bool = Field(description="True when the adapted vector beat or matched the static baseline.")
    samples: int
    attacks: int
    normals: int
    max_fpr: float
    seed: int
    search_evaluations: int
    bounds: Dict[str, Tuple[float, float]]


def calibrate_threshold(
    scores: Sequence[float],
    labels: Sequence[int],
    max_fpr: float = 0.001,
) -> ThresholdCalibration:
    """Choose the threshold maximizing F1 subject to ``FPR <= max_fpr``.

    ``scores`` must be anomaly-oriented: higher means more likely malicious.
    Ties are resolved toward higher recall.  If no threshold meets the FPR
    ceiling, an unreachable threshold is returned (predict nothing).
    """
    scores_arr = np.asarray(scores, dtype=float)
    labels_arr = np.asarray(labels, dtype=int)
    if len(scores_arr) != len(labels_arr):
        raise ValueError("scores and labels must have equal length")
    if len(scores_arr) == 0:
        raise ValueError("Cannot calibrate a threshold on zero samples")
    if not np.isin(labels_arr, (0, 1)).all():
        raise ValueError("Labels must be binary (0=normal, 1=attack)")

    normals = int((labels_arr == 0).sum())
    attacks = int((labels_arr == 1).sum())
    if normals == 0 or attacks == 0:
        raise ValueError("Threshold calibration requires both normal and attack labels")

    order = np.argsort(-scores_arr, kind="mergesort")
    sorted_scores = scores_arr[order]
    sorted_labels = labels_arr[order]

    tp = 0
    fp = 0
    best: Optional[ThresholdCalibration] = None
    idx = 0
    while idx < len(sorted_scores):
        group_score = sorted_scores[idx]
        group_end = idx
        while group_end < len(sorted_scores) and sorted_scores[group_end] == group_score:
            if sorted_labels[group_end] == 1:
                tp += 1
            else:
                fp += 1
            group_end += 1

        predicted = group_end
        fpr = fp / normals
        if fpr <= max_fpr + 1e-12:
            recall = tp / attacks
            precision = tp / predicted if predicted > 0 else 0.0
            f1 = (2.0 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
            candidate = ThresholdCalibration(
                threshold=float(group_score),
                f1=round(f1, 6),
                recall=round(recall, 6),
                precision=round(precision, 6),
                false_positive_rate=round(fpr, 6),
            )
            if (
                best is None
                or candidate.f1 > best.f1 + 1e-12
                or (abs(candidate.f1 - best.f1) <= 1e-12 and candidate.recall > best.recall)
            ):
                best = candidate
        idx = group_end

    if best is None:
        return ThresholdCalibration(
            threshold=float(np.max(scores_arr)) + 1e-9,
            f1=0.0,
            recall=0.0,
            precision=0.0,
            false_positive_rate=0.0,
        )
    return best


def project_weights(
    weights: Sequence[float],
    bounds: Optional[Dict[str, Tuple[float, float]]] = None,
) -> Dict[str, float]:
    """Project arbitrary layer scores onto the bounded probability simplex."""
    bounds = bounds or FUSION_WEIGHT_BOUNDS
    lows = np.array([bounds[key][0] for key in FUSION_WEIGHT_KEYS], dtype=float)
    highs = np.array([bounds[key][1] for key in FUSION_WEIGHT_KEYS], dtype=float)
    if lows.sum() > 1.0 + 1e-9 or highs.sum() < 1.0 - 1e-9:
        raise ValueError("Fusion weight bounds do not admit a normalized vector")

    vector = np.asarray(weights, dtype=float)
    if vector.shape != (len(FUSION_WEIGHT_KEYS),):
        raise ValueError(f"Expected {len(FUSION_WEIGHT_KEYS)} weights")
    vector = np.nan_to_num(vector, nan=0.0, posinf=0.0, neginf=0.0)
    vector = np.clip(vector, lows, highs)

    for _ in range(200):
        total = vector.sum()
        if abs(total - 1.0) <= 1e-10:
            break
        if total < 1.0:
            free = highs - vector
            free_sum = free.sum()
            if free_sum <= 1e-12:
                break
            vector = vector + (1.0 - total) * (free / free_sum)
        else:
            free = vector - lows
            free_sum = free.sum()
            if free_sum <= 1e-12:
                break
            vector = vector - (total - 1.0) * (free / free_sum)
        vector = np.clip(vector, lows, highs)

    vector = np.clip(vector, lows, highs)
    vector = vector / vector.sum()
    # Re-clip once after normalization; then verify the invariant.
    vector = np.clip(vector, lows, highs)
    if abs(vector.sum() - 1.0) > 1e-6:
        raise ValueError("Unable to project weights onto the bounded simplex")
    return {key: float(vector[i]) for i, key in enumerate(FUSION_WEIGHT_KEYS)}


def _row_scores(row: Dict[str, Any]) -> Tuple[float, float, float, float, int]:
    """Extract layer scores and label from a collected layer-output row."""
    semantic = row.get("semantic")
    temporal = row.get("temporal")
    structural = row.get("structural")
    ml = row.get("ml")
    if any(item is None for item in (semantic, temporal, structural, ml)):
        raise ValueError("Each row must contain ml, semantic, temporal, and structural outputs")
    label = row.get("label", row.get("ground_truth_label"))
    if label is None:
        raise ValueError("Each row must contain a trusted 'label' or 'ground_truth_label'")
    label = int(label)
    if label not in (0, 1):
        raise ValueError("Trusted labels must be binary (0=normal, 1=attack)")
    return (
        float(semantic.semantic_score),
        float(temporal.temporal_score),
        float(structural.structural_score),
        float(ml.anomaly_score),
        label,
    )


def collect_layer_outputs(
    records: Sequence[Any],
    ml_detector: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """Replay records through the four stateless/stateful layers only.

    No decision engine or audit log is involved.  The returned rows let an
    experiment compare weight vectors on identical layer evidence.
    """
    from app.defender.ml_detector import MLDetector
    from app.defender.semantic import SemanticEngine
    from app.defender.structural import StructuralEngine
    from app.defender.temporal import TemporalEngine

    detector = ml_detector or MLDetector()
    semantic_engine = SemanticEngine()
    temporal_engine = TemporalEngine()
    structural_engine = StructuralEngine()

    rows: List[Dict[str, Any]] = []
    previous = None
    history: List[Any] = []
    for record in records:
        observation = (
            record.get_inference_observation()
            if hasattr(record, "get_inference_observation")
            else getattr(record, "observation", record)
        )
        ml = detector.analyze(observation)
        semantic = semantic_engine.analyze(observation, previous_obs=previous, history=history)
        structural = structural_engine.analyze(semantic_result=semantic, ml_result=ml)
        temporal = temporal_engine.update(
            step=observation.step,
            semantic_result=semantic,
            ml_result=ml,
            structural_result=structural,
        )
        label = int(getattr(record, "ground_truth_label", 0))
        attack_type = getattr(record, "attack_type", None) or "normal"
        rows.append(
            {
                "label": label,
                "attack_type": attack_type,
                "observation": observation,
                "ml": ml,
                "semantic": semantic,
                "temporal": temporal,
                "structural": structural,
            }
        )
        previous = observation
        history.append(observation)
        if len(history) > settings.HISTORY_BUFFER_SIZE:
            history.pop(0)
    return rows


def evaluate_decision_rows(
    rows: Sequence[Dict[str, Any]],
    engine: JointDecisionEngine,
    mode: str = "rule",
    threshold: Optional[float] = None,
) -> Dict[str, Any]:
    """Evaluate a decision engine on collected rows using rule or risk criterion."""
    if mode not in ("rule", "risk"):
        raise ValueError("mode must be 'rule' or 'risk'")
    if mode == "risk" and threshold is None:
        raise ValueError("risk mode requires a calibrated threshold")

    y_true: List[int] = []
    y_pred: List[int] = []
    class_true: Dict[str, List[int]] = {}
    class_pred: Dict[str, List[int]] = {}
    scores: List[float] = []

    for row in rows:
        decision = engine.decide(
            ml=row["ml"],
            semantic=row["semantic"],
            temporal=row["temporal"],
            structural=row["structural"],
        )
        if mode == "rule":
            predicted = int(decision.classification in ("POTENTIAL_ATTACK", "COORDINATED_ATTACK"))
        else:
            predicted = int(decision.risk_score >= threshold)
        label_value = row.get("label", row.get("ground_truth_label"))
        if label_value is None:
            raise ValueError("Each row must contain a trusted 'label' or 'ground_truth_label'")
        label = int(label_value)
        attack_type = row.get("attack_type") or "normal"
        y_true.append(label)
        y_pred.append(predicted)
        scores.append(float(decision.risk_score))
        if label == 1:
            class_true.setdefault(attack_type, []).append(1)
            class_pred.setdefault(attack_type, []).append(predicted)

    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    total = len(y_true)
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    per_class_recall = {}
    for attack_type, truths in class_true.items():
        preds = class_pred.get(attack_type, [])
        per_class_recall[attack_type] = (
            sum(1 for p in preds if p == 1) / len(truths) if truths else 0.0
        )

    return {
        "mode": mode,
        "threshold": threshold,
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
        "per_class_recall": {k: round(v, 4) for k, v in sorted(per_class_recall.items())},
        "mean_risk_score": round(float(np.mean(scores)), 4) if scores else 0.0,
    }


def adapt_weights(
    rows: Sequence[Dict[str, Any]],
    max_fpr: float = settings.ADAPTIVE_FUSION_MAX_FPR,
    seed: int = settings.ADAPTIVE_FUSION_SEED,
    baseline_weights: Optional[Dict[str, float]] = None,
    random_candidates: int = 200,
    coordinate_rounds: int = 2,
) -> AdaptiveFusionResult:
    """Search bounded fusion weights using trusted labels and FPR ceiling.

    The objective is weighted-risk F1 with a hard validation FPR cap.  The
    static vector is retained unless the adapted vector is at least as good,
    so this routine cannot silently degrade the deployed configuration.
    """
    if not rows:
        raise ValueError("At least one trusted validation row is required")
    baseline_weights = dict(baseline_weights or DEFAULT_FUSION_WEIGHTS)
    validate_fusion_weights(baseline_weights)

    labels = []
    matrix = []
    for row in rows:
        semantic, temporal, structural, ml, label = _row_scores(row)
        matrix.append([semantic, temporal, structural, ml])
        labels.append(label)
    matrix_arr = np.asarray(matrix, dtype=float)
    labels_arr = np.asarray(labels, dtype=int)
    if labels_arr.sum() == 0 or labels_arr.sum() == len(labels_arr):
        raise ValueError("Trusted validation labels must contain both normals and attacks")

    def evaluate(vector: Dict[str, float]) -> Dict[str, Any]:
        ordered = np.array([vector[key] for key in FUSION_WEIGHT_KEYS], dtype=float)
        # Mirror JointDecisionEngine.decide: clamp, then round to 3 decimals.
        risk_scores = np.round(np.clip(matrix_arr @ ordered, 0.0, 1.0), 3)
        calibration = calibrate_threshold(risk_scores, labels_arr, max_fpr=max_fpr)
        return {
            "weights": vector,
            "threshold": calibration.threshold,
            "f1": calibration.f1,
            "recall": calibration.recall,
            "precision": calibration.precision,
            "fpr": calibration.false_positive_rate,
        }

    baseline = evaluate(project_weights([baseline_weights[k] for k in FUSION_WEIGHT_KEYS]))
    best = dict(baseline)
    evaluations = 1
    rng = np.random.default_rng(seed)

    # Broad deterministic search over the bounded simplex.
    for _ in range(random_candidates):
        raw = rng.dirichlet(np.ones(len(FUSION_WEIGHT_KEYS)))
        candidate = project_weights(raw)
        metrics = evaluate(candidate)
        evaluations += 1
        if metrics["f1"] > best["f1"] + 1e-12 or (
            abs(metrics["f1"] - best["f1"]) <= 1e-12 and metrics["recall"] > best["recall"] + 1e-12
        ):
            best = metrics

    # Local coordinate refinement around the best vector.
    for _ in range(coordinate_rounds):
        improved = False
        current = np.array([best["weights"][k] for k in FUSION_WEIGHT_KEYS], dtype=float)
        for index, key in enumerate(FUSION_WEIGHT_KEYS):
            low, high = FUSION_WEIGHT_BOUNDS[key]
            for value in np.linspace(low, high, 9):
                trial = current.copy()
                trial[index] = value
                vector = project_weights(trial)
                metrics = evaluate(vector)
                evaluations += 1
                if metrics["f1"] > best["f1"] + 1e-12 or (
                    abs(metrics["f1"] - best["f1"]) <= 1e-12
                    and metrics["recall"] > best["recall"] + 1e-12
                ):
                    best = metrics
                    improved = True
        if not improved:
            break

    adopted = best["f1"] > baseline["f1"] + 1e-12 or (
        abs(best["f1"] - baseline["f1"]) <= 1e-12 and best["recall"] > baseline["recall"] + 1e-12
    )
    chosen = best if adopted else baseline
    return AdaptiveFusionResult(
        weights={k: round(float(chosen["weights"][k]), 8) for k in FUSION_WEIGHT_KEYS},
        threshold=float(chosen["threshold"]),
        validation_f1=float(chosen["f1"]),
        validation_recall=float(chosen["recall"]),
        validation_precision=float(chosen["precision"]),
        validation_fpr=float(chosen["fpr"]),
        baseline_weights={k: float(baseline_weights[k]) for k in FUSION_WEIGHT_KEYS},
        baseline_threshold=float(baseline["threshold"]),
        baseline_f1=float(baseline["f1"]),
        baseline_recall=float(baseline["recall"]),
        baseline_precision=float(baseline["precision"]),
        baseline_fpr=float(baseline["fpr"]),
        adopted=adopted,
        samples=len(labels_arr),
        attacks=int(labels_arr.sum()),
        normals=int(len(labels_arr) - labels_arr.sum()),
        max_fpr=float(max_fpr),
        seed=int(seed),
        search_evaluations=evaluations,
        bounds={k: FUSION_WEIGHT_BOUNDS[k] for k in FUSION_WEIGHT_KEYS},
    )


def apply_to_engine(result: AdaptiveFusionResult, engine: JointDecisionEngine) -> None:
    """Apply a validated adaptive weight vector to a decision engine."""
    engine.update_weights(result.weights)
