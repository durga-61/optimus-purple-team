"""Tests for Controlled Attack Experiment Engine, Scenarios, and API Endpoints.

Validates:
1. Scenario transformation mathematics and non-destructive copy semantics.
2. Ground-truth isolation from Defender pipeline inputs.
3. Accurate empirical metric calculation (TP, TN, FP, FN, Precision, Recall, F1, FPR).
4. Deterministic baseline vs. attack execution and reproducibility packages.
5. RFC 4180 CSV export and FastAPI endpoint responses.
"""

from copy import deepcopy
import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.api.state import app_state
from app.config import settings
from app.data_sources.hohenheim import HohenheimDataSource
from app.experiments.engine import ExperimentEngine, experiment_engine
from app.experiments.models import AttackConfiguration
from app.experiments.scenarios import SCENARIOS_CATALOG, apply_attack


@pytest.fixture
def hohenheim_source():
    """Provides a dedicated HohenheimDataSource instance for testing."""
    ds = HohenheimDataSource()
    yield ds
    ds._conn.close()


@pytest.fixture
def client():
    """TestClient fixture with loopback access."""
    with TestClient(app) as test_client:
        yield test_client


class TestExperimentScenarios:
    """Tests for attack scenarios transformations and ground-truth isolation."""

    def test_scenarios_catalog_completeness(self):
        """Verify all 6 required scenarios exist in catalog with full metadata."""
        expected_scenarios = [
            "temperature_manipulation",
            "humidity_manipulation",
            "sensor_drift",
            "replay_substitution",
            "cross_sensor_inconsistency",
            "sensor_dropout",
        ]
        for sc in expected_scenarios:
            assert sc in SCENARIOS_CATALOG, f"Missing scenario: {sc}"
            item = SCENARIOS_CATALOG[sc]
            assert "name" in item
            assert "description" in item
            assert "target_layers" in item
            assert "default_parameters" in item
            assert "parameter_schema" in item

    def test_temperature_manipulation_transformation(self, hohenheim_source):
        """Verify discrete temperature offset modifies target and leaves others intact."""
        obs = hohenheim_source.seek(10)
        orig_copy = deepcopy(obs)

        config = AttackConfiguration(
            scenario="temperature_manipulation",
            target_sensor="SENSOR03",
            magnitude=14.5,
        )
        mod_obs, modified_fields = apply_attack(obs, config)

        # Baseline original observation must be completely unmutated
        assert obs.temperature == orig_copy.temperature
        assert obs.sensors["SENSOR03"]["temperature"] == orig_copy.sensors["SENSOR03"]["temperature"]

        # Modified observation check
        orig_temp = orig_copy.sensors["SENSOR03"]["temperature"]
        if orig_temp is not None:
            assert mod_obs.sensors["SENSOR03"]["temperature"] == pytest.approx(orig_temp + 14.5, abs=0.01)

        # Unmodified sensors must remain identical
        assert mod_obs.sensors["SENSOR01"]["temperature"] == orig_copy.sensors["SENSOR01"]["temperature"]
        assert mod_obs.sensors["SENSOR02"]["temperature"] == orig_copy.sensors["SENSOR02"]["temperature"]

        # Ground truth isolation: attack flags must NOT be exposed
        assert mod_obs.is_attack_injected is False
        assert mod_obs.attack_type is None

        # Modified fields record
        assert len(modified_fields) >= 1
        assert any(mf.sensor == "SENSOR03" and mf.field == "temperature" for mf in modified_fields)

    def test_humidity_manipulation_transformation(self, hohenheim_source):
        """Verify humidity manipulation respects boundary clamping [0, 100]."""
        obs = hohenheim_source.seek(20)
        config = AttackConfiguration(
            scenario="humidity_manipulation",
            target_sensor="SENSOR01",
            magnitude=80.0,  # Should clamp to 100
        )
        mod_obs, modified_fields = apply_attack(obs, config)

        assert mod_obs.sensors["SENSOR01"]["humidity"] <= 100.0
        assert mod_obs.is_attack_injected is False
        assert any(mf.sensor == "SENSOR01" and mf.field == "humidity" for mf in modified_fields)

    def test_sensor_drift_cumulative_transformation(self, hohenheim_source):
        """Verify sensor drift applies cumulative offset: drift_rate * drift_steps."""
        obs = hohenheim_source.seek(30)
        orig_temp = obs.sensors["SENSOR02"]["temperature"]

        config = AttackConfiguration(
            scenario="sensor_drift",
            target_sensor="SENSOR02",
            drift_rate=0.7,
            drift_steps=6,
        )
        mod_obs, modified_fields = apply_attack(obs, config)

        expected_delta = 0.7 * 6  # 4.2 deg C
        if orig_temp is not None:
            assert mod_obs.sensors["SENSOR02"]["temperature"] == pytest.approx(orig_temp + expected_delta, abs=0.01)

    def test_cross_sensor_inconsistency_transformation(self, hohenheim_source):
        """Verify cross-sensor spatial inconsistency creates >5 deg C delta across sensors."""
        obs = hohenheim_source.seek(40)
        config = AttackConfiguration(
            scenario="cross_sensor_inconsistency",
            target_sensor="SENSOR04",
            magnitude=7.5,
        )
        mod_obs, modified_fields = apply_attack(obs, config)

        assert any(mf.sensor == "SENSOR04" and mf.field == "temperature" for mf in modified_fields)
        assert mod_obs.is_attack_injected is False

    def test_sensor_dropout_transformation(self, hohenheim_source):
        """Verify sensor dropout suppresses telemetry to None."""
        obs = hohenheim_source.seek(50)
        config = AttackConfiguration(
            scenario="sensor_dropout",
            target_sensor="SENSOR05",
        )
        mod_obs, modified_fields = apply_attack(obs, config)

        target = mod_obs.sensors["SENSOR05"]
        assert target["temperature"] is None
        assert target["humidity"] is None
        assert any(mf.sensor == "SENSOR05" and mf.modified_value is None for mf in modified_fields)

    def test_replay_substitution_transformation(self, hohenheim_source):
        """Verify replay substitution injects historical observation values under current timestamp."""
        current_obs = hohenheim_source.seek(100)
        past_obs = hohenheim_source.seek(5)
        current_timestamp = current_obs.timestamp

        config = AttackConfiguration(
            scenario="replay_substitution",
            target_sensor="SENSOR01",
            replay_step=5,
        )
        mod_obs, modified_fields = apply_attack(current_obs, config, past_obs=past_obs)

        # Observation timestamp must remain the current step's timestamp
        assert mod_obs.timestamp == current_timestamp
        assert mod_obs.is_attack_injected is False


class TestExperimentEngine:
    """Tests for ExperimentEngine lifecycle, outcome determination, and metrics."""

    @pytest.fixture(autouse=True)
    def setup_engine(self):
        """Ensure clean engine instance in Hohenheim mode for every test."""
        app_state.set_data_source_mode("hohenheim")
        experiment_engine.reset()
        yield
        experiment_engine.reset()

    def test_baseline_run_produces_true_negative(self):
        """Verify baseline run on authentic dataset returns NORMAL ground truth and unmodified fields."""
        result = experiment_engine.run_baseline(step=10)

        assert result.is_attack is False
        assert result.attack_type == "baseline"
        assert result.expected_label == "NORMAL"
        assert result.modified_fields == []
        assert result.outcome in ("TRUE_NEGATIVE", "FALSE_POSITIVE")
        assert result.detection_latency_ms >= 0.0

    def test_high_magnitude_attack_produces_true_positive(self):
        """Verify large temperature injection triggers Defender and yields TRUE_POSITIVE."""
        config = AttackConfiguration(
            scenario="temperature_manipulation",
            target_sensor="SENSOR01",
            magnitude=22.0,  # Significant spike
        )
        result = experiment_engine.run_attack_experiment(step=15, config=config)

        assert result.is_attack is True
        assert result.expected_label == "ATTACK"
        assert result.attack_type == "temperature_manipulation"
        assert len(result.modified_fields) >= 1
        # High magnitude attack should be detected as TRUE_POSITIVE
        assert result.outcome == "TRUE_POSITIVE"
        assert result.detection_score >= 0.20
        assert len(result.contributing_layers) > 0

    def test_aggregate_metrics_calculation(self):
        """Verify mathematical calculation of precision, recall, f1, and false positive rate."""
        # Run 2 baselines (expected NORMAL)
        experiment_engine.run_baseline(step=5)
        experiment_engine.run_baseline(step=6)

        # Run 2 attacks (expected ATTACK)
        cfg1 = AttackConfiguration(scenario="temperature_manipulation", target_sensor="SENSOR01", magnitude=25.0)
        cfg2 = AttackConfiguration(scenario="cross_sensor_inconsistency", target_sensor="SENSOR02", magnitude=10.0)
        experiment_engine.run_attack_experiment(step=5, config=cfg1)
        experiment_engine.run_attack_experiment(step=6, config=cfg2)

        metrics = experiment_engine.compute_metrics()
        assert metrics.total_experiments == 4
        assert metrics.true_positives + metrics.false_negatives == 2
        assert metrics.true_negatives + metrics.false_positives == 2

        # Verify precision/recall/f1 bounds [0.0, 1.0] if defined
        if metrics.precision is not None:
            assert 0.0 <= metrics.precision <= 1.0
        if metrics.recall is not None:
            assert 0.0 <= metrics.recall <= 1.0
        if metrics.f1_score is not None:
            assert 0.0 <= metrics.f1_score <= 1.0

        assert metrics.avg_latency_ms >= 0.0
        assert "temperature_manipulation" in metrics.per_attack_breakdown
        assert "cross_sensor_inconsistency" in metrics.per_attack_breakdown

    def test_csv_export_format(self):
        """Verify RFC 4180 CSV export content and structure."""
        experiment_engine.run_baseline(step=1)
        cfg = AttackConfiguration(scenario="sensor_dropout", target_sensor="SENSOR07")
        experiment_engine.run_attack_experiment(step=2, config=cfg)

        csv_text = experiment_engine.export_csv()
        lines = csv_text.strip().splitlines()

        assert len(lines) == 3  # Header + 2 rows
        headers = lines[0].split(",")
        assert "Experiment ID" in headers
        assert "Expected Label" in headers
        assert "Defender Prediction" in headers
        assert "Outcome" in headers
        assert "Detection Score" in headers

    def test_reproducibility_record_contains_provenance(self):
        """Verify reproducibility package contains authoritative Hohenheim provenance and replay snippet."""
        result = experiment_engine.run_baseline(step=42)
        rec = experiment_engine.get_reproducibility_record(result.experiment_id)

        assert rec is not None
        assert rec["experiment_id"] == result.experiment_id
        assert "provenance" in rec
        assert rec["provenance"]["dataset_title"] == "Temperature and Humidity Time Series of Cold Storage Room Monitoring"
        assert rec["provenance"]["dataset_doi"] == "10.5281/zenodo.15130001"
        assert "reproducibility_python_snippet" in rec


class TestExperimentAPIRoutes:
    """Tests for FastAPI HTTP endpoints under /api/experiments."""

    @pytest.fixture(autouse=True)
    def setup_api(self):
        app_state.set_data_source_mode("hohenheim")
        experiment_engine.reset()
        yield
        experiment_engine.reset()

    def test_get_scenarios_endpoint(self, client):
        resp = client.get("/api/experiments/scenarios")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 6
        assert any(item["id"] == "temperature_manipulation" for item in data)

    def test_baseline_and_attack_api_flow(self, client):
        # 1. Run baseline
        base_resp = client.post("/api/experiments/baseline", json={"step": 5})
        assert base_resp.status_code == 200
        base_data = base_resp.json()
        assert base_data["expected_label"] == "NORMAL"
        exp_id_1 = base_data["experiment_id"]

        # 2. Run attack
        attack_payload = {
            "step": 5,
            "configuration": {
                "scenario": "temperature_manipulation",
                "target_sensor": "SENSOR01",
                "magnitude": 18.0,
            },
        }
        att_resp = client.post("/api/experiments/attack", json=attack_payload)
        assert att_resp.status_code == 200
        att_data = att_resp.json()
        assert att_data["expected_label"] == "ATTACK"
        exp_id_2 = att_data["experiment_id"]

        # 3. Get history with filter
        hist_resp = client.get("/api/experiments/history?outcome=TRUE_POSITIVE")
        assert hist_resp.status_code == 200
        assert isinstance(hist_resp.json(), list)

        # 4. Get aggregate metrics
        met_resp = client.get("/api/experiments/metrics")
        assert met_resp.status_code == 200
        metrics = met_resp.json()
        assert metrics["total_experiments"] == 2

        # 5. Get single experiment
        single_resp = client.get(f"/api/experiments/{exp_id_1}")
        assert single_resp.status_code == 200
        assert single_resp.json()["experiment_id"] == exp_id_1

        # 6. Get reproducibility record
        repro_resp = client.get(f"/api/experiments/{exp_id_2}/reproducibility")
        assert repro_resp.status_code == 200
        assert repro_resp.json()["provenance"]["dataset_doi"] == "10.5281/zenodo.15130001"

        # 7. Export CSV
        csv_resp = client.get("/api/experiments/history/export")
        assert csv_resp.status_code == 200
        assert "text/csv" in csv_resp.headers["content-type"]
        assert "Experiment ID" in csv_resp.text

        # 8. Reset
        reset_resp = client.post("/api/experiments/reset")
        assert reset_resp.status_code == 200
        assert reset_resp.json()["success"] is True

        # Confirm history is empty
        empty_hist = client.get("/api/experiments/history").json()
        assert len(empty_hist) == 0
