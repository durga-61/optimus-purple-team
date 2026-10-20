"""Tests for JointDecisionEngine combining multi-stage pipeline evidence."""

import pytest
from app.defender.decision import JointDecisionEngine
from app.defender.models import (
    ConstraintResult,
    MLResult,
    SemanticResult,
    StructuralResult,
    TemporalResult,
)


class TestJointDecisionEngine:
    """Test suite for joint security decision making."""

    @pytest.fixture
    def decision_engine(self):
        return JointDecisionEngine()

    def test_decision_normal_clean_state(self, decision_engine):
        ml = MLResult(anomaly_score=0.08, is_anomaly=False, status="NORMAL")
        sem = SemanticResult(
            semantic_score=0.0,
            status="NORMAL",
            constraints=[],
            violated_constraints=[],
            evidence={},
            explanation="Normal",
        )
        temp = TemporalResult(temporal_score=0.0, persistence=0, status="STABLE")
        struct = StructuralResult(structural_score=0.0, status="ISOLATED")

        dec = decision_engine.decide(ml, sem, temp, struct)
        assert dec.classification == "NORMAL"
        assert dec.integrity_score >= 95.0
        assert "NORMAL:" in dec.explanation

    def test_decision_potential_attack_on_semantic_violation(self, decision_engine):
        c1 = ConstraintResult(
            constraint="C1",
            name="Capacity",
            status="VIOLATED",
            expected=50.0,
            actual=84.0,
            difference=34.0,
            tolerance=0.5,
            message="44.3 + 40 > 50",
        )
        sem = SemanticResult(
            semantic_score=0.50,
            status="VIOLATION",
            constraints=[c1],
            violated_constraints=["C1"],
            evidence={},
            explanation="C1 violated",
        )
        ml = MLResult(anomaly_score=0.20, is_anomaly=False, status="NORMAL")
        temp = TemporalResult(temporal_score=0.25, persistence=1, status="ELEVATED")
        struct = StructuralResult(structural_score=0.35, status="CORRELATED", affected_nodes=["inventory_ledger"])

        dec = decision_engine.decide(ml, sem, temp, struct)
        assert dec.classification == "POTENTIAL_ATTACK"
        assert dec.integrity_score < 75.0
        assert "POTENTIAL DATA INTEGRITY ATTACK" in dec.explanation
        assert "44.3 + 40 > 50" in dec.explanation

    def test_decision_coordinated_attack_on_multi_source_and_persistence(self, decision_engine):
        c1 = ConstraintResult(
            constraint="C1",
            name="Capacity",
            status="VIOLATED",
            expected=50.0,
            actual=84.0,
            difference=34.0,
            tolerance=0.5,
            message="C1 violated",
        )
        sem = SemanticResult(
            semantic_score=0.70,
            status="VIOLATION",
            constraints=[c1],
            violated_constraints=["C1"],
            evidence={},
            explanation="C1 violated",
        )
        ml = MLResult(anomaly_score=0.85, is_anomaly=True, status="ANOMALY")
        temp = TemporalResult(temporal_score=0.65, persistence=4, recurrence=4, status="ESCALATING")
        struct = StructuralResult(
            structural_score=0.80,
            status="MULTI_SOURCE",
            affected_nodes=["inventory_ledger", "environmental_iot"],
        )

        dec = decision_engine.decide(ml, sem, temp, struct)
        assert dec.classification == "COORDINATED_ATTACK"
        assert dec.integrity_score < 50.0
        assert "COORDINATED ATTACK DETECTED" in dec.explanation

    def test_decision_low_risk_on_mild_warning(self, decision_engine):
        c3 = ConstraintResult(
            constraint="C3",
            name="Historical",
            status="WARNING",
            expected={},
            actual={},
            difference=1.0,
            tolerance=0.0,
            message="Mild temperature drift",
        )
        sem = SemanticResult(
            semantic_score=0.15,
            status="WARNING",
            constraints=[c3],
            violated_constraints=[],
            evidence={},
            explanation="C3 warning",
        )
        ml = MLResult(anomaly_score=0.15, is_anomaly=False, status="NORMAL")
        temp = TemporalResult(temporal_score=0.0, persistence=0, status="STABLE")
        struct = StructuralResult(structural_score=0.0, status="ISOLATED")

        dec = decision_engine.decide(ml, sem, temp, struct)
        assert dec.classification == "LOW"
        assert dec.integrity_score > 85.0
