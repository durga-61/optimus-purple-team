"""Tests for trusted-label adaptive fusion of the four detection layers."""

from types import SimpleNamespace

import numpy as np
import pytest

from app.defender.adaptive_fusion import (
    DEFAULT_FUSION_WEIGHTS,
    adapt_weights,
    calibrate_threshold,
    evaluate_decision_rows,
    project_weights,
)
from app.defender.decision import (
    FUSION_WEIGHT_BOUNDS,
    FUSION_WEIGHT_KEYS,
    JointDecisionEngine,
    validate_fusion_weights,
)
from app.defender.models import MLResult, SemanticResult, StructuralResult, TemporalResult


def _row(semantic: float, temporal: float, structural: float, ml: float, label: int):
    return {
        "semantic": SimpleNamespace(semantic_score=semantic),
        "temporal": SimpleNamespace(temporal_score=temporal),
        "structural": SimpleNamespace(structural_score=structural),
        "ml": SimpleNamespace(anomaly_score=ml),
        "label": label,
        "attack_type": "test_attack" if label else "normal",
    }


class TestFusionWeightSafety:
    def test_default_weights_are_valid_and_normalized(self):
        validated = validate_fusion_weights(DEFAULT_FUSION_WEIGHTS)
        assert set(validated) == set(FUSION_WEIGHT_KEYS)
        assert sum(validated.values()) == pytest.approx(1.0)
        for key, value in validated.items():
            low, high = FUSION_WEIGHT_BOUNDS[key]
            assert low <= value <= high

    @pytest.mark.parametrize(
        "weights",
        [
            {"semantic": 0.40, "temporal": 0.25, "structural": 0.20},
            {"semantic": -0.10, "temporal": 0.45, "structural": 0.35, "ml": 0.30},
            {"semantic": 0.90, "temporal": 0.05, "structural": 0.03, "ml": 0.02},
            {"semantic": 0.50, "temporal": 0.30, "structural": 0.30, "ml": 0.10},
        ],
    )
    def test_update_weights_rejects_unsafe_vectors(self, weights):
        engine = JointDecisionEngine()
        before = engine.get_weights()
        with pytest.raises(ValueError):
            engine.update_weights(weights)
        assert engine.get_weights() == before

    def test_update_weights_is_atomic_and_visible_in_evidence(self):
        engine = JointDecisionEngine()
        weights = {"semantic": 0.34, "temporal": 0.34, "structural": 0.27, "ml": 0.05}
        engine.update_weights(weights)
        assert engine.get_weights() == pytest.approx(weights)
        decision = engine.decide()
        assert decision.contributing_evidence["fusion_weights"] == pytest.approx(weights)

    def test_project_weights_always_returns_bounded_simplex(self):
        rng = np.random.default_rng(7)
        for _ in range(200):
            raw = rng.normal(size=len(FUSION_WEIGHT_KEYS)) * rng.choice([1.0, 10.0, 100.0])
            projected = project_weights(raw)
            assert set(projected) == set(FUSION_WEIGHT_KEYS)
            assert sum(projected.values()) == pytest.approx(1.0, abs=1e-6)
            for key, value in projected.items():
                low, high = FUSION_WEIGHT_BOUNDS[key]
                assert low - 1e-9 <= value <= high + 1e-9

    def test_project_weights_handles_non_finite_values(self):
        projected = project_weights([float("nan"), float("inf"), -50.0, 100.0])
        assert sum(projected.values()) == pytest.approx(1.0, abs=1e-6)
        assert all(np.isfinite(list(projected.values())))


class TestThresholdCalibration:
    def test_calibration_respects_fpr_ceiling(self):
        scores = [0.05, 0.10, 0.20, 0.85, 0.90, 0.95]
        labels = [0, 0, 0, 1, 1, 1]
        result = calibrate_threshold(scores, labels, max_fpr=0.0)
        assert result.false_positive_rate == 0.0
        assert result.recall == 1.0
        assert result.f1 == 1.0
        assert result.threshold == 0.85

    def test_calibration_picks_best_f1_under_ceiling(self):
        scores = [0.10, 0.30, 0.50, 0.70]
        labels = [0, 0, 1, 1]
        result = calibrate_threshold(scores, labels, max_fpr=0.5)
        assert result.false_positive_rate <= 0.5
        assert result.f1 == pytest.approx(1.0)
        assert result.threshold == 0.50

    def test_calibration_requires_both_classes(self):
        with pytest.raises(ValueError):
            calibrate_threshold([0.1, 0.2], [0, 0])
        with pytest.raises(ValueError):
            calibrate_threshold([], [])

    def test_calibration_rejects_non_binary_labels(self):
        with pytest.raises(ValueError):
            calibrate_threshold([0.1, 0.9], [0, 2])

    def test_unreachable_fpr_ceiling_predicts_nothing(self):
        result = calibrate_threshold([0.9, 0.8], [0, 1], max_fpr=-0.1)
        assert result.f1 == 0.0
        assert result.threshold > 0.9


class TestAdaptiveWeightSearch:
    def _rows(self):
        rows = []
        for _ in range(20):
            rows.append(_row(semantic=0.0, temporal=0.6, structural=0.0, ml=0.1, label=0))
            rows.append(_row(semantic=0.9, temporal=0.7, structural=0.2, ml=0.2, label=1))
        return rows

    def test_adapt_weights_returns_safe_nondegrading_vector(self):
        rows = self._rows()
        result = adapt_weights(rows, max_fpr=0.0, random_candidates=30, coordinate_rounds=1)
        assert sum(result.weights.values()) == pytest.approx(1.0, abs=1e-6)
        for key, value in result.weights.items():
            low, high = FUSION_WEIGHT_BOUNDS[key]
            assert low - 1e-9 <= value <= high + 1e-9
        assert result.validation_f1 >= result.baseline_f1
        assert result.validation_fpr <= result.max_fpr + 1e-12
        assert result.search_evaluations > 1
        if not result.adopted:
            assert result.weights == pytest.approx(result.baseline_weights)

    def test_adapt_weights_is_deterministic_for_a_seed(self):
        rows = self._rows()
        first = adapt_weights(rows, max_fpr=0.0, seed=11, random_candidates=20, coordinate_rounds=1)
        second = adapt_weights(rows, max_fpr=0.0, seed=11, random_candidates=20, coordinate_rounds=1)
        assert first.weights == second.weights
        assert first.threshold == second.threshold

    def test_adapt_weights_requires_trusted_labels_from_both_classes(self):
        with pytest.raises(ValueError):
            adapt_weights([])
        with pytest.raises(ValueError):
            adapt_weights(
                [_row(0.1, 0.1, 0.1, 0.1, label=0) for _ in range(10)],
                random_candidates=1,
                coordinate_rounds=0,
            )
        with pytest.raises(ValueError):
            adapt_weights(
                [_row(0.1, 0.1, 0.1, 0.1, label=0), _row(0.9, 0.9, 0.9, 0.9, label=2)],
                random_candidates=1,
                coordinate_rounds=0,
            )


class TestDecisionRowEvaluation:
    def _rows(self):
        normal = {
            "ml": MLResult(anomaly_score=0.05),
            "semantic": SemanticResult(semantic_score=0.0),
            "temporal": TemporalResult(temporal_score=0.0),
            "structural": StructuralResult(structural_score=0.0),
            "label": 0,
            "attack_type": "normal",
        }
        attack = {
            "ml": MLResult(anomaly_score=0.8, is_anomaly=True),
            "semantic": SemanticResult(
                semantic_score=1.0,
                status="VIOLATION",
                violated_constraints=["C1"],
            ),
            "temporal": TemporalResult(temporal_score=0.8, status="ESCALATING"),
            "structural": StructuralResult(structural_score=0.6, status="CORRELATED"),
            "label": 1,
            "attack_type": "test_attack",
        }
        return [normal, attack]

    def test_rule_mode_reports_confusion_counts(self):
        metrics = evaluate_decision_rows(self._rows(), JointDecisionEngine(), mode="rule")
        assert metrics["total_samples"] == 2
        assert metrics["recall"] == 1.0
        assert metrics["false_positive_rate"] == 0.0
        assert metrics["per_class_recall"] == {"test_attack": 1.0}

    def test_risk_mode_requires_threshold_and_uses_it(self):
        with pytest.raises(ValueError):
            evaluate_decision_rows(self._rows(), JointDecisionEngine(), mode="risk")
        metrics = evaluate_decision_rows(
            self._rows(), JointDecisionEngine(), mode="risk", threshold=0.99
        )
        assert metrics["recall"] == 0.0
        assert metrics["false_positive_rate"] == 0.0

    def test_accepts_ground_truth_label_alias(self):
        rows = self._rows()
        for row in rows:
            row["ground_truth_label"] = row.pop("label")
        metrics = evaluate_decision_rows(rows, JointDecisionEngine(), mode="rule")
        assert metrics["recall"] == 1.0
