"""Tests for StructuralEngine evaluating organizational graph dependencies."""

import pytest
from app.defender.models import ConstraintResult, MLResult, SemanticResult
from app.defender.structural import StructuralEngine


class TestStructuralEngine:
    """Test suite for structural graph analysis."""

    @pytest.fixture
    def structural_engine(self):
        return StructuralEngine()

    def test_clean_state_is_isolated(self, structural_engine):
        sem_res = SemanticResult(
            semantic_score=0.0,
            status="NORMAL",
            constraints=[],
            violated_constraints=[],
            evidence={},
            explanation="Clean",
        )
        ml_res = MLResult(anomaly_score=0.1, is_anomaly=False, status="NORMAL")

        res = structural_engine.analyze(sem_res, ml_res)
        assert res.status == "ISOLATED"
        assert res.structural_score == 0.0
        assert len(res.affected_nodes) == 0
        assert len(res.correlated_edges) == 0

    def test_c1_capacity_violation_activates_ledger_nodes(self, structural_engine):
        c1 = ConstraintResult(
            constraint="C1",
            name="Capacity",
            status="VIOLATED",
            expected=50.0,
            actual=84.0,
            difference=34.0,
            tolerance=0.5,
            message="Violated",
        )
        sem_res = SemanticResult(
            semantic_score=0.6,
            status="VIOLATION",
            constraints=[c1],
            violated_constraints=["C1"],
            evidence={},
            explanation="C1 Violated",
        )
        ml_res = MLResult(anomaly_score=0.1, is_anomaly=False, status="NORMAL")

        res = structural_engine.analyze(sem_res, ml_res)
        assert res.status == "CORRELATED"
        assert "inventory_ledger" in res.affected_nodes
        assert "capacity_management" in res.affected_nodes
        assert len(res.correlated_edges) > 0
        assert res.structural_score > 0.20

    def test_multi_source_manipulation_activates_cross_subsystem_correlation(self, structural_engine):
        c1 = ConstraintResult(
            constraint="C1",
            name="Capacity",
            status="VIOLATED",
            expected=50.0,
            actual=84.0,
            difference=34.0,
            tolerance=0.5,
            message="Violated",
        )
        c3 = ConstraintResult(
            constraint="C3",
            name="Historical",
            status="VIOLATED",
            expected={},
            actual={},
            difference=1.0,
            tolerance=0.0,
            message="Temp violated",
        )
        sem_res = SemanticResult(
            semantic_score=0.8,
            status="VIOLATION",
            constraints=[c1, c3],
            violated_constraints=["C1", "C3"],
            evidence={},
            explanation="Multi violated",
        )
        # High ML anomaly on sensor
        ml_res = MLResult(anomaly_score=0.85, is_anomaly=True, status="ANOMALY")

        res = structural_engine.analyze(sem_res, ml_res)
        assert res.status == "MULTI_SOURCE"
        assert "inventory_ledger" in res.affected_nodes
        assert "environmental_iot" in res.affected_nodes
        assert res.structural_score >= 0.50
        assert "Multi-source structural correlation" in res.explanation
