"""Comprehensive regression and fusion integration test suite.

Validates:
1. Multi-layer fusion engine without semantic gating.
2. Sensor spoofing multi-step persistence escalation to primary alert vs single-step triage.
3. Normal environmental variation yields 0 false positives.
4. Conflicting signals: isolated ML outlier does not generate false primary alerts.
5. Missing or invalid detector outputs degrade gracefully with safe defaults.
6. Repeated temporal events accumulate persistence and recover cleanly upon decay.
7. Coordinated weak and multi-source attack classifications.
"""

import pytest
from app.defender.decision import JointDecisionEngine
from app.defender.models import (
    ConstraintResult,
    MLResult,
    SecurityDecision,
    SemanticResult,
    StructuralResult,
    TemporalResult,
)
from app.defender.service import DefenderService
from app.simulator.scenarios import (
    inject_capacity_manipulation,
    inject_coordinated_manipulation,
    inject_multi_source_manipulation,
    inject_sensor_spoofing,
)
from app.simulator.warehouse import ColdStorageWarehouse


class TestFusionIntegrationRegression:
    """Regression test suite for centralized multi-layer defender fusion."""

    @pytest.fixture
    def decision_engine(self):
        return JointDecisionEngine()

    @pytest.fixture
    def service(self):
        return DefenderService()

    # 1. Normal Observations
    def test_normal_environmental_variation_does_not_false_positive(self, service):
        """Clean telemetry with normal baseline noise remains strictly NORMAL with 0 alerts."""
        wh = ColdStorageWarehouse(seed=123)
        for _ in range(10):
            obs = wh.step()
            res = service.analyze(obs)
            assert res.decision.classification == "NORMAL"
            assert res.decision.risk_score < 0.20
            assert res.decision.integrity_score >= 90.0
            assert len(res.alerts) == 0

        assert len(service.get_alerts(active_only=True)) == 0

    # 2. Strong Independent Finding Not Discarded Without C1/C2
    def test_strong_independent_detection_without_semantic_violation(self, decision_engine):
        """When ML is anomalous, structural is correlated, and temporal is escalating,

        the fusion engine must issue a primary alert even if C1 and C2 are satisfied.
        """
        ml = MLResult(anomaly_score=0.88, is_anomaly=True, status="ANOMALY")
        sem = SemanticResult(
            semantic_score=0.15,
            status="WARNING",
            constraints=[
                ConstraintResult(
                    constraint="C3",
                    name="Historical",
                    status="WARNING",
                    expected={"temp": [1.0, 7.0]},
                    actual={"temp": 24.5},
                    difference=1.0,
                    tolerance=0.0,
                    message="Temperature outside safe cold-storage bounds",
                )
            ],
            violated_constraints=[],
            evidence={"temperature": 24.5},
            explanation="C3 environmental warning",
        )
        temp = TemporalResult(
            temporal_score=0.72,
            persistence=4,
            recurrence=4,
            status="ESCALATING",
        )
        struct = StructuralResult(
            structural_score=0.60,
            status="CORRELATED",
            affected_nodes=["environmental_iot", "historical_profile"],
            correlated_edges=[["environmental_iot", "historical_profile"]],
            explanation="Correlated environmental anomaly",
        )

        decision = decision_engine.decide(ml=ml, semantic=sem, temporal=temp, structural=struct)

        # Must NOT be silenced into SUSPICIOUS or LOW
        assert decision.classification in ("POTENTIAL_ATTACK", "COORDINATED_ATTACK")
        assert decision.risk_score >= 0.40
        assert decision.integrity_score <= 60.0
        assert "POTENTIAL" in decision.classification or "COORDINATED" in decision.classification

        # Evidence from all 4 layers preserved
        ev = decision.contributing_evidence
        assert ev["ml"]["is_anomaly"] is True
        assert ev["temporal"]["status"] == "ESCALATING"
        assert ev["structural"]["status"] == "CORRELATED"
        assert "environmental_iot" in ev["structural"]["affected_nodes"]

    # 3. Sensor Spoofing Progression: Triage -> Primary Alert
    def test_sensor_spoofing_escalates_from_triage_to_primary_alert(self, service):
        """Step 1 of sensor spoofing is a triage finding (SUSPICIOUS);

        sustained attack over steps 2+ escalates to POTENTIAL_ATTACK primary alert.
        """
        wh = ColdStorageWarehouse(seed=42)
        service.analyze(wh.get_current_observation())

        # Step 1: Initial excursion
        step1 = wh.step()
        spoofed1 = inject_sensor_spoofing(step1, spoofed_temperature=22.0, spoofed_humidity=96.0)
        res1 = service.analyze(spoofed1)

        # Isolated step -> SUSPICIOUS triage finding, no primary alert
        assert res1.decision.classification in ("SUSPICIOUS", "LOW")
        assert res1.temporal.status == "STABLE"

        # Step 2: Sustained attack
        step2 = wh.step()
        spoofed2 = inject_sensor_spoofing(step2, spoofed_temperature=22.5, spoofed_humidity=96.5)
        res2 = service.analyze(spoofed2)

        # Sustained attack -> temporal state escalates to ELEVATED/ESCALATING -> primary alert
        assert res2.temporal.status in ("ELEVATED", "ESCALATING")
        assert res2.structural.status == "CORRELATED"
        assert res2.decision.classification == "POTENTIAL_ATTACK"
        assert len(res2.alerts) == 1
        assert res2.alerts[0].severity == "HIGH"

    # 4. Conflicting Signals: Isolated ML Outlier
    def test_conflicting_signals_isolated_ml_outlier_does_not_false_alarm(self, decision_engine):
        """A single statistical ML outlier without physical violation, temporal persistence,

        or structural correlation must classify as SUSPICIOUS or LOW, not POTENTIAL_ATTACK.
        """
        ml = MLResult(anomaly_score=0.72, is_anomaly=True, status="ANOMALY")
        sem = SemanticResult(
            semantic_score=0.0,
            status="NORMAL",
            constraints=[],
            violated_constraints=[],
            evidence={},
            explanation="All constraints passed",
        )
        temp = TemporalResult(temporal_score=0.0, persistence=0, status="STABLE")
        struct = StructuralResult(structural_score=0.0, status="ISOLATED", affected_nodes=[])

        decision = decision_engine.decide(ml=ml, semantic=sem, temporal=temp, structural=struct)

        # Crucial for 0.00% FPR: must NOT trigger a primary alert
        assert decision.classification not in ("POTENTIAL_ATTACK", "COORDINATED_ATTACK")
        assert decision.classification in ("SUSPICIOUS", "LOW")
        assert decision.risk_score < 0.25

    # 5. Missing Layer Outputs Gracefully Handled
    def test_missing_detector_outputs_handled_gracefully(self, decision_engine):
        """Engine safely defaults missing layer outputs without crashing."""
        # Completely empty call
        dec_empty = decision_engine.decide(ml=None, semantic=None, temporal=None, structural=None)
        assert dec_empty.classification == "NORMAL"
        assert dec_empty.risk_score == 0.0
        assert dec_empty.integrity_score == 100.0

        # Only ML provided
        ml = MLResult(anomaly_score=0.90, is_anomaly=True, status="ANOMALY")
        dec_ml_only = decision_engine.decide(ml=ml, semantic=None, temporal=None, structural=None)
        assert dec_ml_only.classification in ("SUSPICIOUS", "LOW")
        assert dec_ml_only.risk_score > 0.0

        # Only Semantic violation provided
        c1 = ConstraintResult(
            constraint="C1",
            name="Capacity",
            status="VIOLATED",
            expected=50.0,
            actual=75.0,
            difference=25.0,
            tolerance=0.5,
            message="Capacity breach",
        )
        sem = SemanticResult(
            semantic_score=0.50,
            status="VIOLATION",
            constraints=[c1],
            violated_constraints=["C1"],
            evidence={},
            explanation="C1 violated",
        )
        dec_sem_only = decision_engine.decide(ml=None, semantic=sem, temporal=None, structural=None)
        assert dec_sem_only.classification == "POTENTIAL_ATTACK"

    # 6. Repeated Temporal Events and Decay Recovery
    def test_repeated_temporal_events_escalate_and_recover(self, service):
        """Attacks accumulate temporal persistence and decay back to NORMAL after recovery."""
        wh = ColdStorageWarehouse(seed=42)
        service.analyze(wh.get_current_observation())

        # Attack phase: 3 consecutive capacity violations
        for _ in range(3):
            obs = wh.step()
            attack_obs = inject_capacity_manipulation(obs, reported_free_capacity=45.0)
            res = service.analyze(attack_obs)
            assert res.decision.classification == "POTENTIAL_ATTACK"

        assert service.temporal_engine.consecutive_violations == 3
        assert service.temporal_engine.window[-1]["is_violation"] is True

        # Recovery phase: clean steps
        for _ in range(12):
            rec_obs = wh.step()
            res = service.analyze(rec_obs)

        # After sliding window clears, state returns to NORMAL
        latest = service.get_latest_analysis()
        assert latest.decision.classification == "NORMAL"
        assert latest.temporal.status == "STABLE"
        assert latest.temporal.temporal_score == 0.0
        assert latest.temporal.persistence == 0

    # 7. Coordinated Weak Attack Tracking
    def test_coordinated_weak_attack_flow(self, service):
        """Coordinated weak manipulation is detected on onset and monitored."""
        wh = ColdStorageWarehouse(seed=42)
        service.analyze(wh.get_current_observation())

        step1 = wh.step()
        coord_obs = inject_coordinated_manipulation(step1, inventory_delta=-2.0, reported_free_capacity_delta=1.0)
        res = service.analyze(coord_obs)

        # Discrepancy = 1.0 > 0.5t tolerance -> triggers C1 violation
        assert "C1" in res.semantic.violated_constraints
        assert res.decision.classification == "POTENTIAL_ATTACK"
        assert len(res.alerts) >= 1

    # 8. Multi-Source Attack Produces COORDINATED_ATTACK
    def test_multi_source_attack_produces_coordinated_attack(self, service):
        """Simultaneous manipulation of operational ledger and physical sensors

        with temporal escalation triggers COORDINATED_ATTACK and CRITICAL alert.
        """
        wh = ColdStorageWarehouse(seed=42)
        service.analyze(wh.get_current_observation())

        # Step 1: multi-source injection
        obs1 = wh.step()
        res1 = service.analyze(inject_multi_source_manipulation(obs1))

        # Step 2: sustained multi-source injection
        obs2 = wh.step()
        res2 = service.analyze(inject_multi_source_manipulation(obs2))

        assert res2.structural.status == "MULTI_SOURCE"
        assert res2.temporal.status in ("ELEVATED", "ESCALATING")
        assert res2.decision.classification == "COORDINATED_ATTACK"
        assert len(res2.alerts) == 1
        assert res2.alerts[0].severity == "CRITICAL"
