"""Evaluation foundation, dataset generation, and performance benchmark package."""

from app.evaluation.dataset import (
    EvaluationRecord,
    EvaluationDataset,
    DatasetSplits,
    generate_normal_dataset,
    generate_attack_dataset,
    create_temporal_splits,
)
from app.evaluation.metrics import (
    ClassificationMetrics,
    LatencyMetrics,
    AttackClassMetrics,
    EvaluationSummary,
    compute_classification_metrics,
    compute_latency_metrics,
)

__all__ = [
    "EvaluationRecord",
    "EvaluationDataset",
    "DatasetSplits",
    "generate_normal_dataset",
    "generate_attack_dataset",
    "create_temporal_splits",
    "ClassificationMetrics",
    "LatencyMetrics",
    "AttackClassMetrics",
    "EvaluationSummary",
    "compute_classification_metrics",
    "compute_latency_metrics",
]
