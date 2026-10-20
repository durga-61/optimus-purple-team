"""Tests for TemporalEngine tracking persistence, frequency, and decay."""

import pytest
from app.defender.models import ConstraintResult, MLResult, SemanticResult
from app.defender.temporal import TemporalEngine


class TestTemporalEngine:
    """Test suite for temporal escalation and decay logic."""

    @pytest.fixture
    def temporal_engine(self):
        return TemporalEngine(window_size=10, decay_factor=0.85)

    def _make_semantic_result(self, is_violation: bool) -> SemanticResult:
        if is_violation:
            c = ConstraintResult(
                constraint="C1",
                name="Capacity",
                status="VIOLATED",
                expected=50.0,
                actual=84.0,
                difference=34.0,
                tolerance=0.5,
                message="Capacity violation",
            )
            return SemanticResult(
                semantic_score=0.80,
                status="VIOLATION",
                constraints=[c],
                violated_constraints=["C1"],
                evidence={},
                explanation="Violated",
            )
        return SemanticResult(
            semantic_score=0.0,
            status="NORMAL",
            constraints=[],
            violated_constraints=[],
            evidence={},
            explanation="Normal",
        )

    def _make_ml_result(self, is_anomaly: bool) -> MLResult:
        return MLResult(
            anomaly_score=0.85 if is_anomaly else 0.10,
            is_anomaly=is_anomaly,
            status="ANOMALY" if is_anomaly else "NORMAL",
            features_evaluated=[],
            details={},
        )

    def test_clean_series_remains_stable(self, temporal_engine):
        clean_sem = self._make_semantic_result(is_violation=False)
        clean_ml = self._make_ml_result(is_anomaly=False)

        for step in range(1, 6):
            res = temporal_engine.update(step, clean_sem, clean_ml)

        assert res.status == "STABLE"
        assert res.temporal_score == 0.0
        assert res.persistence == 0
        assert res.recurrence == 0

    def test_temporal_persistence_increases_with_consecutive_violations(self, temporal_engine):
        viol_sem = self._make_semantic_result(is_violation=True)
        clean_ml = self._make_ml_result(is_anomaly=False)

        res1 = temporal_engine.update(1, viol_sem, clean_ml)
        assert res1.persistence == 1

        res2 = temporal_engine.update(2, viol_sem, clean_ml)
        assert res2.persistence == 2
        assert res2.temporal_score > res1.temporal_score

        res3 = temporal_engine.update(3, viol_sem, clean_ml)
        assert res3.persistence == 3
        assert res3.status == "ESCALATING"

    def test_temporal_decay_resets_persistence_and_lowers_score(self, temporal_engine):
        viol_sem = self._make_semantic_result(is_violation=True)
        clean_sem = self._make_semantic_result(is_violation=False)
        clean_ml = self._make_ml_result(is_anomaly=False)

        # Single violation at step 1
        res_attack = temporal_engine.update(1, viol_sem, clean_ml)
        score_at_attack = res_attack.temporal_score
        assert res_attack.persistence == 1

        # Subsequent normal steps
        decay_res = None
        for step in range(2, 8):
            decay_res = temporal_engine.update(step, clean_sem, clean_ml)
            assert decay_res.persistence == 0  # Persistence immediately breaks

        # Temporal score should have decayed substantially
        assert decay_res.temporal_score < score_at_attack
        assert decay_res.status in ("STABLE", "ELEVATED")
