"""Evaluation metrics computation for industrial cybersecurity monitoring benchmarks.

Computes Detection Rate, FPR, FNR, Precision, Recall, F1-Score, Detection Latency,
per-attack-class performance, and multi-stage ablation metrics.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Optional


@dataclass
class ClassificationMetrics:
    """Standard binary classification metrics with zero-division protections."""

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    total: int = 0
    detection_rate: float = 0.0  # Recall (TP / (TP + FN))
    false_positive_rate: float = 0.0  # FPR (FP / (FP + TN))
    false_negative_rate: float = 0.0  # FNR (FN / (TP + FN))
    precision: float = 0.0  # Precision (TP / (TP + FP))
    recall: float = 0.0  # Recall (TP / (TP + FN))
    f1_score: float = 0.0  # Harmonic mean of Precision and Recall
    accuracy: float = 0.0  # (TP + TN) / Total

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "total": self.total,
            "detection_rate": round(self.detection_rate, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_negative_rate": round(self.false_negative_rate, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "accuracy": round(self.accuracy, 4),
        }


@dataclass
class LatencyMetrics:
    """Detection latency metrics measuring step delays from attack onset to detection."""

    mean_latency: float = 0.0
    median_latency: float = 0.0
    p95_latency: float = 0.0
    min_latency: float = 0.0
    max_latency: float = 0.0
    detected_episodes: int = 0
    total_episodes: int = 0
    episode_detection_rate: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mean_latency": round(self.mean_latency, 2),
            "median_latency": round(self.median_latency, 2),
            "p95_latency": round(self.p95_latency, 2),
            "min_latency": round(self.min_latency, 2),
            "max_latency": round(self.max_latency, 2),
            "detected_episodes": self.detected_episodes,
            "total_episodes": self.total_episodes,
            "episode_detection_rate": round(self.episode_detection_rate, 4),
        }


@dataclass
class AttackClassMetrics:
    """Comprehensive performance metrics for a specific attack class."""

    attack_class: str
    total_samples: int
    detected_samples: int
    detection_rate: float
    precision: float
    recall: float
    f1_score: float
    latency: LatencyMetrics

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_class": self.attack_class,
            "total_samples": self.total_samples,
            "detected_samples": self.detected_samples,
            "detection_rate": round(self.detection_rate, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            **self.latency.to_dict(),
        }


@dataclass
class EvaluationSummary:
    """Aggregate benchmark results across overall, per-class, and ablation dimensions."""

    split_name: str
    overall: ClassificationMetrics
    latency: LatencyMetrics
    per_class: Dict[str, AttackClassMetrics]
    ablation: Dict[str, ClassificationMetrics]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "split_name": self.split_name,
            "timestamp": self.timestamp,
            "overall": self.overall.to_dict(),
            "latency": self.latency.to_dict(),
            "per_class": {k: v.to_dict() for k, v in self.per_class.items()},
            "ablation": {k: v.to_dict() for k, v in self.ablation.items()},
        }


def compute_classification_metrics(y_true: List[int], y_pred: List[int]) -> ClassificationMetrics:
    """Compute mathematical classification metrics from ground-truth and binary predictions."""
    if len(y_true) != len(y_pred):
        raise ValueError(f"Length mismatch: y_true ({len(y_true)}) != y_pred ({len(y_pred)})")

    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)
    total = len(y_true)

    # Protected mathematical computations
    detection_rate = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    recall = detection_rate
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0

    if (precision + recall) > 0:
        f1_score = 2.0 * (precision * recall) / (precision + recall)
    else:
        f1_score = 0.0

    accuracy = (tp + tn) / total if total > 0 else 0.0

    return ClassificationMetrics(
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        total=total,
        detection_rate=detection_rate,
        false_positive_rate=fpr,
        false_negative_rate=fnr,
        precision=precision,
        recall=recall,
        f1_score=f1_score,
        accuracy=accuracy,
    )


def compute_latency_metrics(latencies: List[Optional[int]], total_episodes: int) -> LatencyMetrics:
    """Compute summary statistics for episode detection latencies."""
    valid_latencies = [l for l in latencies if l is not None]
    detected_episodes = len(valid_latencies)

    if not valid_latencies:
        return LatencyMetrics(
            mean_latency=0.0,
            median_latency=0.0,
            p95_latency=0.0,
            min_latency=0.0,
            max_latency=0.0,
            detected_episodes=0,
            total_episodes=total_episodes,
            episode_detection_rate=0.0,
        )

    valid_latencies.sort()
    n = len(valid_latencies)
    mean_lat = sum(valid_latencies) / n

    # Median
    if n % 2 == 1:
        med_lat = float(valid_latencies[n // 2])
    else:
        med_lat = (valid_latencies[n // 2 - 1] + valid_latencies[n // 2]) / 2.0

    # 95th percentile
    p95_idx = min(n - 1, math.ceil(0.95 * n) - 1)
    p95_lat = float(valid_latencies[p95_idx])

    return LatencyMetrics(
        mean_latency=mean_lat,
        median_latency=med_lat,
        p95_latency=p95_lat,
        min_latency=float(valid_latencies[0]),
        max_latency=float(valid_latencies[-1]),
        detected_episodes=detected_episodes,
        total_episodes=total_episodes,
        episode_detection_rate=detected_episodes / total_episodes if total_episodes > 0 else 0.0,
    )
