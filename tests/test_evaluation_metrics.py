"""Tests for Evaluation Metrics and Latency Calculations.

Verifies:
- Mathematical accuracy of Detection Rate, FPR, FNR, Precision, Recall, F1, Accuracy.
- Zero-division safety under edge cases (all-normal, all-attack, zero-detection).
- Episode latency computation (mean, median, P95, min, max, episode detection rate).
- Integration of EvaluationEngine on synthetic observations.
"""

import pytest

from app.evaluation.dataset import (
    create_temporal_splits,
    generate_attack_dataset,
    generate_normal_dataset,
)
from app.evaluation.evaluator import EvaluationEngine
from app.evaluation.metrics import (
    compute_classification_metrics,
    compute_latency_metrics,
)


class TestMathematicalMetricCorrectness:
    """Verify standard classification metrics against analytical values."""

    def test_known_confusion_matrix_metrics(self):
        """Metrics match analytical formulas exactly for known TP, FP, TN, FN values."""
        # TP=80, FN=20 (100 actual attacks)
        # FP=10, TN=90 (100 actual normal)
        y_true = [1] * 80 + [1] * 20 + [0] * 10 + [0] * 90
        y_pred = [1] * 80 + [0] * 20 + [1] * 10 + [0] * 90

        m = compute_classification_metrics(y_true, y_pred)

        assert m.tp == 80
        assert m.fn == 20
        assert m.fp == 10
        assert m.tn == 90
        assert m.total == 200

        # Mathematical checks
        assert pytest.approx(m.detection_rate, 1e-4) == 0.8000
        assert pytest.approx(m.recall, 1e-4) == 0.8000
        assert pytest.approx(m.false_positive_rate, 1e-4) == 0.1000
        assert pytest.approx(m.false_negative_rate, 1e-4) == 0.2000
        assert pytest.approx(m.precision, 1e-4) == 80.0 / 90.0
        expected_f1 = 2.0 * (80.0 / 90.0 * 0.80) / (80.0 / 90.0 + 0.80)
        assert pytest.approx(m.f1_score, 1e-4) == expected_f1
        assert pytest.approx(m.accuracy, 1e-4) == 170.0 / 200.0

    def test_perfect_classification_metrics(self):
        """Perfect predictions yield 1.0 precision, recall, F1, and 0.0 FPR."""
        y_true = [1] * 50 + [0] * 50
        y_pred = [1] * 50 + [0] * 50

        m = compute_classification_metrics(y_true, y_pred)
        assert m.detection_rate == 1.0
        assert m.precision == 1.0
        assert m.recall == 1.0
        assert m.f1_score == 1.0
        assert m.false_positive_rate == 0.0
        assert m.false_negative_rate == 0.0
        assert m.accuracy == 1.0

    def test_zero_division_safety_all_normal(self):
        """When evaluation contains zero attacks, metrics do not crash with ZeroDivisionError."""
        y_true = [0] * 100
        y_pred = [0] * 100

        m = compute_classification_metrics(y_true, y_pred)
        assert m.detection_rate == 0.0
        assert m.false_positive_rate == 0.0
        assert m.false_negative_rate == 0.0
        assert m.precision == 0.0
        assert m.recall == 0.0
        assert m.f1_score == 0.0
        assert m.accuracy == 1.0

    def test_zero_division_safety_no_positive_predictions(self):
        """When defender flags zero samples, precision and F1 return 0.0 gracefully."""
        y_true = [1] * 50 + [0] * 50
        y_pred = [0] * 100

        m = compute_classification_metrics(y_true, y_pred)
        assert m.tp == 0
        assert m.fp == 0
        assert m.precision == 0.0
        assert m.detection_rate == 0.0
        assert m.f1_score == 0.0
        assert m.false_positive_rate == 0.0
        assert m.false_negative_rate == 1.0


class TestLatencyMetricsComputation:
    """Verify episode latency summary statistics."""

    def test_latency_statistics_with_detected_and_undetected_episodes(self):
        """Computes mean, median, P95, min, max, and episode detection rate correctly."""
        # 5 detected episodes with step delays [1, 2, 4, 5, 8] and 1 undetected episode (None)
        latencies = [1, 2, 4, 5, 8, None]
        total_episodes = 6

        lat = compute_latency_metrics(latencies, total_episodes)

        assert lat.detected_episodes == 5
        assert lat.total_episodes == 6
        assert pytest.approx(lat.episode_detection_rate, 1e-4) == 5.0 / 6.0
        assert lat.min_latency == 1.0
        assert lat.max_latency == 8.0
        assert pytest.approx(lat.mean_latency, 1e-4) == (1 + 2 + 4 + 5 + 8) / 5.0  # 4.0
        assert lat.median_latency == 4.0

    def test_latency_statistics_all_undetected(self):
        """When zero episodes are detected, latency metrics return 0.0 safely."""
        lat = compute_latency_metrics([None, None, None], 3)
        assert lat.detected_episodes == 0
        assert lat.total_episodes == 3
        assert lat.episode_detection_rate == 0.0
        assert lat.mean_latency == 0.0
        assert lat.median_latency == 0.0


class TestEvaluationEngineIntegration:
    """Verify end-to-end evaluation engine on a mini dataset."""

    def test_engine_executes_mini_benchmark(self):
        """EvaluationEngine processes mini dataset, fits ML on train, and returns valid summary."""
        normal_records = generate_normal_dataset(num_samples=40, seed=42)
        attack_records = generate_attack_dataset(num_samples_per_class=12, seed=42, episode_length=6)


        splits = create_temporal_splits(
            normal_records=normal_records,
            attack_records=attack_records,
            train_ratio=0.50,
            val_ratio=0.25,
            test_ratio=0.25,
        )

        engine = EvaluationEngine(training_records=splits.train, random_state=42)
        summary, detailed = engine.evaluate_split(splits.val, split_name="val")

        # Verify summary structure
        assert summary.split_name == "val"
        assert summary.overall.total == len(splits.val)
        assert 0.0 <= summary.overall.detection_rate <= 1.0
        assert 0.0 <= summary.overall.precision <= 1.0
        assert 0.0 <= summary.overall.f1_score <= 1.0
        assert 0.0 <= summary.overall.false_positive_rate <= 1.0

        # Verify per-class metrics exist for all 6 classes
        assert len(summary.per_class) == 6
        for c in summary.per_class:
            assert summary.per_class[c].total_samples > 0

        # Verify all 8 ablation configurations exist
        assert "ml_only" in summary.ablation
        assert "semantic_only" in summary.ablation
        assert "temporal_only" in summary.ablation
        assert "structural_only" in summary.ablation
        assert "semantic_plus_temporal" in summary.ablation
        assert "semantic_plus_structural" in summary.ablation
        assert "joint_decision" in summary.ablation
        assert "joint_with_suspicious" in summary.ablation

        # Verify detailed predictions match total records and have per-layer flags
        assert len(detailed) == len(splits.val)
        assert "pred_ml" in detailed[0]
        assert "pred_semantic" in detailed[0]
        assert "pred_temporal" in detailed[0]
        assert "pred_structural" in detailed[0]
        assert "pred_joint_with_suspicious" in detailed[0]
