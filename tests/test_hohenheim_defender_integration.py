"""End-to-End integration tests for real Hohenheim dataset through the DefenderService pipeline.

Validates C1/C2 NOT_APPLICABLE status, C3/C4 evaluation, ML anomaly detection,
temporal tracking, structural graph correlation, joint decision fusion, and SHA-256 audit chaining.
"""

import pytest
from app.data_sources.hohenheim import HohenheimDataSource
from app.defender.service import DefenderService
from app.simulator.models import WarehouseObservation


class TestHohenheimDefenderIntegration:
    """End-to-end integration test suite for Hohenheim dataset and DefenderService."""

    @pytest.fixture(scope="class")
    @classmethod
    def setup_pipeline(cls):
        ds = HohenheimDataSource()
        service = DefenderService()
        yield ds, service
        ds._conn.close()

    def test_c1_and_c2_return_not_applicable(self, setup_pipeline):
        """Verify C1 and C2 constraints return NOT_APPLICABLE and zero risk penalty."""
        ds, service = setup_pipeline
        obs = ds.seek(0)
        res = service.analyze(obs)

        c1 = next((c for c in res.semantic.constraints if c.constraint == "C1"), None)
        c2 = next((c for c in res.semantic.constraints if c.constraint == "C2"), None)

        assert c1 is not None
        assert c1.status == "NOT_APPLICABLE"
        assert "not applicable" in c1.message.lower()

        assert c2 is not None
        assert c2.status == "NOT_APPLICABLE"
        assert "not applicable" in c2.message.lower()

        # Neither C1 nor C2 should be flagged as violated
        assert "C1" not in res.semantic.violated_constraints
        assert "C2" not in res.semantic.violated_constraints

    def test_c3_and_c4_evaluate_real_telemetry(self, setup_pipeline):
        """Verify C3 evaluates temperature envelope and C4 evaluates spatial multi-sensor delta."""
        ds, service = setup_pipeline
        obs = ds.seek(100)
        res = service.analyze(obs)

        c3 = next((c for c in res.semantic.constraints if c.constraint == "C3"), None)
        c4 = next((c for c in res.semantic.constraints if c.constraint == "C4"), None)

        assert c3 is not None
        assert c3.status in ("PASSED", "WARNING")

        assert c4 is not None
        assert c4.status in ("PASSED", "WARNING", "INSUFFICIENT_DATA")
        if c4.status == "PASSED":
            assert c4.difference == 0.0

    def test_ml_evaluates_environmental_features(self, setup_pipeline):
        """Verify IsolationForest analyzes environmental feature vector without errors."""
        ds, service = setup_pipeline
        obs = ds.seek(200)
        res = service.analyze(obs)

        assert res.ml is not None
        assert 0.0 <= res.ml.anomaly_score <= 1.0
        assert res.ml.status in ("NORMAL", "SUSPICIOUS", "ANOMALY")
        assert "inter_sensor_temp_delta" in res.ml.features_evaluated
        assert res.ml.details.get("mode") == "environmental_multisensor"

    def test_temporal_tracking_and_decay(self, setup_pipeline):
        """Verify temporal engine records chronological observations and decays clean steps."""
        ds, service = setup_pipeline
        service.reset()

        for step in range(5):
            obs = ds.seek(step)
            res = service.analyze(obs)

        assert res.temporal.window_size == 10
        assert 0.0 <= res.temporal.temporal_score <= 1.0
        assert res.temporal.status in ("STABLE", "ELEVATED", "ESCALATING")

    def test_structural_correlation_with_sensor_zones(self, setup_pipeline):
        """Verify structural analyzer evaluates cold-room zones and sensors."""
        ds, service = setup_pipeline
        obs = ds.seek(300)
        res = service.analyze(obs)

        assert res.structural is not None
        assert res.structural.status in ("ISOLATED", "CORRELATED", "MULTI_SOURCE")
        assert isinstance(res.structural.affected_nodes, list)

    def test_joint_decision_classification_validity(self, setup_pipeline):
        """Verify final classification is grounded and explainable."""
        ds, service = setup_pipeline
        obs = ds.seek(400)
        res = service.analyze(obs)

        valid_classifications = {"NORMAL", "LOW", "SUSPICIOUS", "POTENTIAL_ATTACK", "COORDINATED_ATTACK"}
        assert res.decision.classification in valid_classifications
        assert 0.0 <= res.decision.risk_score <= 1.0
        assert 0.0 <= res.decision.integrity_score <= 100.0
        assert res.decision.explanation != ""

    def test_cryptographic_audit_chain_integrity(self, setup_pipeline):
        """Verify SHA-256 hash chaining remains unbroken across real observation evaluations."""
        ds, service = setup_pipeline
        service.reset()

        for step in range(10):
            obs = ds.seek(step)
            service.analyze(obs)

        audit_verification = service.verify_audit_chain()
        assert audit_verification.valid is True
        assert audit_verification.total_events > 0
        assert audit_verification.error is None
        assert len(audit_verification.latest_event_hash) == 64

    def test_door_opening_does_not_trigger_false_attack(self, setup_pipeline):
        """Verify a physical door opening event is explained contextually and not misclassified as a coordinated cyberattack."""
        ds, service = setup_pipeline
        service.reset()

        # Seek to step 835 where Door opened is active
        door_obs = ds.seek(835)
        assert door_obs.active_action == "Door opened"

        res = service.analyze(door_obs)
        # Must not be mislabeled as an attack breach of ledgers
        c1 = next((c for c in res.semantic.constraints if c.constraint == "C1"), None)
        assert c1.status == "NOT_APPLICABLE"
        assert res.decision.classification != "COORDINATED_ATTACK"
