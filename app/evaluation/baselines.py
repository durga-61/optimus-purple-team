"""Independent anomaly-detection baselines for OPTIMUS comparisons.

Implements One-Class SVM and PCA reconstruction-error detectors using the same
seven physical/operational features as the OPTIMUS Isolation Forest.  Both are
fitted on trusted normal training records only and their decision thresholds
are calibrated on an independent validation split under a hard FPR ceiling.
"""

from typing import Any, Dict, List, Optional, Sequence

import numpy as np
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from app.defender.adaptive_fusion import calibrate_threshold
from app.defender.ml_detector import FEATURE_NAMES
from app.evaluation.metrics import compute_classification_metrics


def _as_observation(record: Any) -> Any:
    if hasattr(record, "get_inference_observation"):
        return record.get_inference_observation()
    return getattr(record, "observation", record)


def observation_matrix(records: Sequence[Any]) -> np.ndarray:
    """Extract the shared seven-feature matrix from observations or records."""
    rows = []
    for record in records:
        observation = _as_observation(record)
        rows.append(
            [
                observation.temperature,
                observation.humidity,
                observation.inventory,
                observation.free_capacity,
                observation.inbound,
                observation.outbound,
                observation.occupancy,
            ]
        )
    if not rows:
        return np.empty((0, len(FEATURE_NAMES)), dtype=float)
    return np.asarray(rows, dtype=float)


def _record_labels(records: Sequence[Any]) -> np.ndarray:
    return np.asarray([int(getattr(record, "ground_truth_label", 0)) for record in records], dtype=int)


class _StandardizedDetector:
    """Shared scaling, threshold calibration, and evaluation for sklearn baselines."""

    name = "baseline"

    def __init__(self) -> None:
        self.scaler = StandardScaler()
        self.threshold: Optional[float] = None
        self.is_fitted = False

    def _fit_model(self, scaled: np.ndarray) -> None:
        raise NotImplementedError

    def _score_model(self, scaled: np.ndarray) -> np.ndarray:
        raise NotImplementedError

    def fit(self, records: Sequence[Any]) -> "_StandardizedDetector":
        if any(int(getattr(record, "ground_truth_label", 0)) == 1 for record in records):
            raise ValueError("Baselines must be fitted on normal records only")
        matrix = observation_matrix(records)
        if len(matrix) < 10:
            raise ValueError("At least 10 normal observations are required to fit a baseline")
        scaled = self.scaler.fit_transform(matrix)
        self._fit_model(scaled)
        self.is_fitted = True
        return self

    def score(self, records: Sequence[Any]) -> np.ndarray:
        if not self.is_fitted:
            raise RuntimeError("Detector must be fitted before scoring")
        matrix = observation_matrix(records)
        if len(matrix) == 0:
            return np.empty(0, dtype=float)
        scaled = self.scaler.transform(matrix)
        return np.asarray(self._score_model(scaled), dtype=float)

    def calibrate(self, records: Sequence[Any], max_fpr: float = 0.001) -> float:
        calibration = calibrate_threshold(self.score(records), _record_labels(records), max_fpr=max_fpr)
        self.threshold = calibration.threshold
        return self.threshold

    def predict(self, records: Sequence[Any], threshold: Optional[float] = None) -> np.ndarray:
        cutoff = threshold if threshold is not None else self.threshold
        if cutoff is None:
            raise RuntimeError("Calibrate the detector or provide a threshold before prediction")
        return (self.score(records) >= cutoff).astype(int)


class OneClassSVMDetector(_StandardizedDetector):
    """One-Class SVM boundary learned from normal observations."""

    name = "one_class_svm"

    def __init__(self, nu: float = 0.03, kernel: str = "rbf", gamma: str = "scale"):
        super().__init__()
        self.nu = nu
        self.kernel = kernel
        self.gamma = gamma
        self.model: Optional[OneClassSVM] = None

    def _fit_model(self, scaled: np.ndarray) -> None:
        self.model = OneClassSVM(nu=self.nu, kernel=self.kernel, gamma=self.gamma)
        self.model.fit(scaled)

    def _score_model(self, scaled: np.ndarray) -> np.ndarray:
        # Higher score means more anomalous.
        return -self.model.decision_function(scaled)


class PCADetector(_StandardizedDetector):
    """PCA reconstruction-error detector fitted on normal observations."""

    name = "pca"

    def __init__(self, n_components: float = 0.95):
        super().__init__()
        self.n_components = n_components
        self.model: Optional[PCA] = None

    def _fit_model(self, scaled: np.ndarray) -> None:
        self.model = PCA(n_components=self.n_components, random_state=42)
        self.model.fit(scaled)

    def _score_model(self, scaled: np.ndarray) -> np.ndarray:
        projected = self.model.transform(scaled)
        reconstructed = self.model.inverse_transform(projected)
        return np.mean((scaled - reconstructed) ** 2, axis=1)


def evaluate_detector(
    detector: _StandardizedDetector,
    records: Sequence[Any],
    threshold: Optional[float] = None,
) -> Dict[str, Any]:
    """Evaluate a fitted baseline with standard OPTIMUS metrics and per-class recall."""
    predictions = detector.predict(records, threshold=threshold)
    labels = _record_labels(records)
    metrics = compute_classification_metrics(labels.tolist(), predictions.tolist())
    scores = detector.score(records)

    per_class_recall: Dict[str, float] = {}
    per_class_evasion: Dict[str, float] = {}
    by_class: Dict[str, List[int]] = {}
    for record, predicted in zip(records, predictions):
        if int(getattr(record, "ground_truth_label", 0)) == 1:
            attack_type = getattr(record, "attack_type", None) or "unknown"
            by_class.setdefault(attack_type, []).append(int(predicted))
    for attack_type, values in sorted(by_class.items()):
        recall = sum(values) / len(values) if values else 0.0
        per_class_recall[attack_type] = round(recall, 4)
        per_class_evasion[attack_type] = round(1.0 - recall, 4)

    return {
        "detector": detector.name,
        "threshold": float(threshold if threshold is not None else detector.threshold),
        "total_samples": metrics.total,
        "tp": metrics.tp,
        "fp": metrics.fp,
        "tn": metrics.tn,
        "fn": metrics.fn,
        "detection_rate": round(metrics.detection_rate, 4),
        "recall": round(metrics.recall, 4),
        "precision": round(metrics.precision, 4),
        "f1": round(metrics.f1_score, 4),
        "false_positive_rate": round(metrics.false_positive_rate, 4),
        "accuracy": round(metrics.accuracy, 4),
        "evasion_rate": round(1.0 - metrics.detection_rate, 4),
        "per_class_recall": per_class_recall,
        "per_class_evasion": per_class_evasion,
        "mean_score": round(float(np.mean(scores)), 4) if len(scores) else 0.0,
        "mean_normal_score": round(float(np.mean(scores[labels == 0])), 4) if (labels == 0).any() else 0.0,
        "mean_attack_score": round(float(np.mean(scores[labels == 1])), 4) if (labels == 1).any() else 0.0,
    }


def fit_baseline_detectors(
    train_records: Sequence[Any],
    validation_records: Sequence[Any],
    max_fpr: float = 0.001,
) -> Dict[str, _StandardizedDetector]:
    """Fit and calibrate both baselines on trusted splits."""
    detectors: Dict[str, _StandardizedDetector] = {
        "one_class_svm": OneClassSVMDetector(),
        "pca": PCADetector(),
    }
    for detector in detectors.values():
        detector.fit(train_records)
        detector.calibrate(validation_records, max_fpr=max_fpr)
    return detectors
