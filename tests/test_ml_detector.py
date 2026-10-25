"""Tests for scikit-learn IsolationForest ML anomaly detector."""

import pytest
from app.defender.ml_detector import MLDetector
from app.simulator.models import WarehouseObservation
from app.simulator.warehouse import ColdStorageWarehouse


class TestMLDetector:
    """Test suite for ML anomaly detection module."""

    @pytest.fixture(scope="class")
    def detector(self):
        return MLDetector(random_state=42)

    def test_detector_initialization_and_fit(self, detector):
        assert detector.is_fitted is True
        assert detector.model is not None
        assert detector.anomaly_threshold == 0.60

    def test_normal_observation_scores_low(self, detector):
        wh = ColdStorageWarehouse(seed=42)
        normal_obs = wh.get_current_observation()

        result = detector.analyze(normal_obs)
        assert result.is_anomaly is False
        assert result.status in ("NORMAL", "SUSPICIOUS")
        assert result.anomaly_score < detector.anomaly_threshold
        assert len(result.features_evaluated) == 7

    def test_extreme_multivariate_outlier_detected(self, detector):
        # Extreme temperature, out-of-whack inventory and shipments
        extreme_obs = WarehouseObservation(
            warehouse="W01",
            capacity=50.0,
            inventory=48.0,
            free_capacity=2.0,
            temperature=38.5,  # extreme heat in cold storage
            humidity=15.0,     # extreme desert dryness
            occupancy=96.0,
            inbound=15.0,
            outbound=20.0,
        )

        result = detector.analyze(extreme_obs)
        assert result.anomaly_score > 0.50
        assert result.status in ("ANOMALY", "SUSPICIOUS")

    def test_detector_does_not_crash_on_edge_cases(self, detector):
        # Near zero boundary values
        edge_obs = WarehouseObservation(
            warehouse="W01",
            capacity=50.0,
            inventory=0.0,
            free_capacity=50.0,
            temperature=0.0,
            humidity=0.0,
            occupancy=0.0,
            inbound=0.0,
            outbound=0.0,
        )
        result = detector.analyze(edge_obs)
        assert isinstance(result.anomaly_score, float)
        assert 0.0 <= result.anomaly_score <= 1.0

    def test_refit_with_observations(self, detector):
        wh = ColdStorageWarehouse(seed=123)
        obs_list = [wh.step() for _ in range(25)]
        detector.fit(obs_list)
        assert detector.is_fitted is True
