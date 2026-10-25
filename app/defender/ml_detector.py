"""Machine Learning anomaly detection component using scikit-learn IsolationForest.

Learns normal multivariate operating patterns of cold-storage warehouse IoT telemetry
and real multi-sensor environmental recordings to detect statistically unusual observations.
Adapts dynamically to both operational warehouse ledger features and multi-sensor
environmental time series without fabricating missing fields.
"""

import logging
from pathlib import Path
import sqlite3
from typing import List, Optional
import numpy as np
from sklearn.ensemble import IsolationForest

from app.config import settings
from app.defender.models import MLResult
from app.simulator.models import WarehouseObservation

logger = logging.getLogger("defender.ml")

LEDGER_FEATURE_NAMES = [
    "temperature",
    "humidity",
    "inventory",
    "free_capacity",
    "inbound",
    "outbound",
    "occupancy",
]

FEATURE_NAMES = LEDGER_FEATURE_NAMES

ENVIRONMENTAL_FEATURE_NAMES = [
    "temperature",
    "humidity",
    "inter_sensor_temp_delta",
    "inter_sensor_hum_delta",
    "spatial_temp_std",
    "active_sensor_ratio",
]

_CACHED_LEDGER_MODEL = None
_CACHED_ENV_MODEL = None


class MLDetector:
    """Unsupervised statistical anomaly detector using scikit-learn IsolationForest.
    
    Maintains dedicated models for:
    1. Operational warehouse observations (with inventory and capacity metrics).
    2. Environmental multi-sensor observations (with spatial gradients and sensor health metrics).
    """

    def __init__(
        self,
        contamination: float = 0.03,
        random_state: int = 42,
        anomaly_threshold: float = 0.60,
    ):
        self.contamination = contamination
        self.random_state = random_state
        self.anomaly_threshold = anomaly_threshold
        self.ledger_model: Optional[IsolationForest] = None
        self.env_model: Optional[IsolationForest] = None
        self.is_fitted = False

        self._fit_on_baselines()

    def _extract_ledger_features(self, obs: WarehouseObservation) -> np.ndarray:
        """Extract ordered numeric feature vector for operational warehouse records."""
        return np.array([
            obs.temperature if obs.temperature is not None else settings.TARGET_TEMPERATURE,
            obs.humidity if obs.humidity is not None else settings.TARGET_HUMIDITY,
            obs.inventory if obs.inventory is not None else settings.DEFAULT_INITIAL_INVENTORY,
            obs.free_capacity if obs.free_capacity is not None else 8.0,
            obs.inbound if obs.inbound is not None else 0.0,
            obs.outbound if obs.outbound is not None else 0.0,
            obs.occupancy if obs.occupancy is not None else 84.0,
        ], dtype=float).reshape(1, -1)

    def _extract_environmental_features(self, obs: WarehouseObservation) -> np.ndarray:
        """Extract ordered numeric feature vector for pure environmental multi-sensor observations."""
        quality = obs.data_quality or {}
        t_delta = quality.get("inter_sensor_temp_delta", 0.0)
        h_delta = quality.get("inter_sensor_hum_delta", 0.0)
        t_std = quality.get("spatial_temp_std", 0.0)
        active_ratio = quality.get("active_sensor_count", 9) / 9.0

        return np.array([
            obs.temperature if obs.temperature is not None else settings.TARGET_TEMPERATURE,
            obs.humidity if obs.humidity is not None else settings.TARGET_HUMIDITY,
            t_delta,
            h_delta,
            t_std,
            active_ratio,
        ], dtype=float).reshape(1, -1)

    def _extract_features(self, obs: WarehouseObservation) -> np.ndarray:
        """Dispatcher extracting appropriate feature vector depending on available fields."""
        if obs.inventory is not None and obs.capacity is not None:
            return self._extract_ledger_features(obs)
        return self._extract_environmental_features(obs)

    def _fit_on_baselines(self, num_samples: int = 120) -> None:
        """Fit or restore cached IsolationForest detectors for both modes."""
        global _CACHED_LEDGER_MODEL, _CACHED_ENV_MODEL

        # 1. Operational Ledger Model
        if _CACHED_LEDGER_MODEL is not None:
            self.ledger_model = _CACHED_LEDGER_MODEL
        else:
            from app.simulator.warehouse import ColdStorageWarehouse
            wh = ColdStorageWarehouse(seed=self.random_state)
            samples = []
            for _ in range(num_samples):
                obs = wh.step()
                samples.append(self._extract_ledger_features(obs)[0])
            self.ledger_model = IsolationForest(
                n_estimators=50,
                contamination=self.contamination,
                random_state=self.random_state,
            )
            self.ledger_model.fit(np.array(samples, dtype=float))
            _CACHED_LEDGER_MODEL = self.ledger_model

        # 2. Environmental Multi-Sensor Model
        if _CACHED_ENV_MODEL is not None:
            self.env_model = _CACHED_ENV_MODEL
        else:
            env_samples = self._collect_environmental_baseline_samples(num_samples)
            self.env_model = IsolationForest(
                n_estimators=50,
                contamination=self.contamination,
                random_state=self.random_state,
            )
            self.env_model.fit(env_samples)
            _CACHED_ENV_MODEL = self.env_model

        self.is_fitted = True

    @property
    def model(self) -> Optional[IsolationForest]:
        """Backward-compatible access to primary ledger IsolationForest model."""
        return self.ledger_model

    def fit(self, observations: List[WarehouseObservation]) -> None:
        """Fit or refit the detector using a list of warehouse observations."""
        if not observations:
            return
        features = [self._extract_features(obs)[0] for obs in observations]
        first_obs = observations[0]
        if first_obs.inventory is not None and first_obs.capacity is not None:
            self.ledger_model = IsolationForest(
                n_estimators=50,
                contamination=self.contamination,
                random_state=self.random_state,
            )
            self.ledger_model.fit(np.array(features, dtype=float))
        else:
            self.env_model = IsolationForest(
                n_estimators=50,
                contamination=self.contamination,
                random_state=self.random_state,
            )
            self.env_model.fit(np.array(features, dtype=float))
        self.is_fitted = True

    def _collect_environmental_baseline_samples(self, num_samples: int = 120) -> np.ndarray:
        """Collect clean normal baseline samples from Hohenheim database or synthetic envelope."""
        project_root = Path(__file__).resolve().parent.parent.parent
        db_path = project_root / settings.HOHENHEIM_DB_PATH

        if db_path.exists():
            try:
                conn = sqlite3.connect(str(db_path))
                cursor = conn.cursor()
                # Query first normal steps (ignoring door actions)
                cursor.execute(
                    "SELECT temp_s1, hum_s1, temp_s2, hum_s2, temp_s6, hum_s6 "
                    "FROM observations WHERE active_action IS NULL LIMIT ?;",
                    (num_samples,),
                )
                rows = cursor.fetchall()
                conn.close()

                if len(rows) >= 20:
                    samples = []
                    for r in rows:
                        t1, h1, t2, h2, t6, h6 = r
                        temps = [t for t in (t1, t2, t6) if t is not None]
                        hums = [h for h in (h1, h2, h6) if h is not None]
                        t_mean = float(np.mean(temps)) if temps else settings.TARGET_TEMPERATURE
                        h_mean = float(np.mean(hums)) if hums else settings.TARGET_HUMIDITY
                        t_delta = float(max(temps) - min(temps)) if len(temps) > 1 else 0.5
                        h_delta = float(max(hums) - min(hums)) if len(hums) > 1 else 2.0
                        t_std = float(np.std(temps)) if len(temps) > 1 else 0.2
                        samples.append([t_mean, h_mean, t_delta, h_delta, t_std, 1.0])
                    return np.array(samples, dtype=float)
            except Exception as e:
                logger.warning(f"Failed to read Hohenheim DB for ML baseline ({e}). Using synthetic baseline.")

        # Fallback synthetic environmental samples within normal cold-room envelope
        rng = np.random.RandomState(self.random_state)
        t_base = rng.normal(settings.TARGET_TEMPERATURE, 0.4, num_samples)
        h_base = rng.normal(settings.TARGET_HUMIDITY, 2.0, num_samples)
        t_deltas = rng.exponential(0.6, num_samples)
        h_deltas = rng.exponential(3.0, num_samples)
        t_stds = rng.exponential(0.3, num_samples)
        ratios = np.ones(num_samples)
        return np.column_stack([t_base, h_base, t_deltas, h_deltas, t_stds, ratios])

    def analyze(self, observation: WarehouseObservation) -> MLResult:
        """Analyze an observation and return a structured MLResult."""
        try:
            is_ledger = observation.inventory is not None and observation.capacity is not None
            active_model = self.ledger_model if is_ledger else self.env_model
            active_features = LEDGER_FEATURE_NAMES if is_ledger else ENVIRONMENTAL_FEATURE_NAMES

            X = self._extract_ledger_features(observation) if is_ledger else self._extract_environmental_features(observation)

            if not self.is_fitted or active_model is None:
                return self._fallback_analyze(observation)

            # IsolationForest decision_function: positive for inliers, negative for outliers
            raw_decision = float(active_model.decision_function(X)[0])

            # Monotonic mapping from decision_function to normalized anomaly score in [0.0, 1.0]
            scale = 12.0
            anomaly_score = float(1.0 / (1.0 + np.exp(scale * raw_decision)))
            anomaly_score = round(max(0.0, min(1.0, anomaly_score)), 3)

            is_anomaly = anomaly_score >= self.anomaly_threshold
            if anomaly_score >= self.anomaly_threshold:
                status = "ANOMALY"
            elif anomaly_score >= 0.40:
                status = "SUSPICIOUS"
            else:
                status = "NORMAL"

            return MLResult(
                anomaly_score=anomaly_score,
                is_anomaly=is_anomaly,
                status=status,
                features_evaluated=active_features,
                details={
                    "raw_decision_function": round(raw_decision, 4),
                    "threshold": self.anomaly_threshold,
                    "model_type": "IsolationForest",
                    "mode": "operational_ledger" if is_ledger else "environmental_multisensor",
                },
            )

        except Exception as e:
            logger.error(f"ML analysis error: {e}. Utilizing fallback scoring.")
            return self._fallback_analyze(observation, str(e))

    def _fallback_analyze(self, observation: WarehouseObservation, error_msg: Optional[str] = None) -> MLResult:
        """Fallback boundary check if model inference fails."""
        anomaly_score = 0.0
        if observation.temperature < settings.TEMP_MIN_BOUND or observation.temperature > settings.TEMP_MAX_BOUND:
            anomaly_score += 0.4
        if observation.humidity < settings.HUMIDITY_MIN_BOUND or observation.humidity > settings.HUMIDITY_MAX_BOUND:
            anomaly_score += 0.3
        anomaly_score = round(min(1.0, anomaly_score), 2)

        is_ledger = observation.inventory is not None
        features = LEDGER_FEATURE_NAMES if is_ledger else ENVIRONMENTAL_FEATURE_NAMES

        return MLResult(
            anomaly_score=anomaly_score,
            is_anomaly=anomaly_score >= self.anomaly_threshold,
            status="ANOMALY" if anomaly_score >= self.anomaly_threshold else "NORMAL",
            features_evaluated=features,
            details={"fallback": True, "error": error_msg},
        )
