"""Machine Learning anomaly detection component using scikit-learn IsolationForest.

Learns normal multivariate operating patterns of cold-storage warehouse IoT telemetry
and operational records to detect statistically unusual observations.
"""

import logging
from typing import List, Optional
import numpy as np
from sklearn.ensemble import IsolationForest

from app.config import settings
from app.defender.models import MLResult
from app.simulator.models import WarehouseObservation

logger = logging.getLogger("defender.ml")

FEATURE_NAMES = [
    "temperature",
    "humidity",
    "inventory",
    "free_capacity",
    "inbound",
    "outbound",
    "occupancy",
]


_CACHED_BASELINE_MODEL = None

class MLDetector:
    """Unsupervised statistical anomaly detector using scikit-learn IsolationForest."""

    def __init__(
        self,
        contamination: float = 0.03,
        random_state: int = 42,
        anomaly_threshold: float = 0.60,
    ):
        self.contamination = contamination
        self.random_state = random_state
        self.anomaly_threshold = anomaly_threshold
        self.model: Optional[IsolationForest] = None
        self.is_fitted = False

        # Initialize and fit on synthetic normal baseline (cached for speed)
        self._fit_on_baseline()

    def _extract_features(self, obs: WarehouseObservation) -> np.ndarray:
        """Extract ordered numeric feature vector from observation."""
        return np.array([
            obs.temperature,
            obs.humidity,
            obs.inventory,
            obs.free_capacity,
            obs.inbound,
            obs.outbound,
            obs.occupancy,
        ], dtype=float).reshape(1, -1)

    def _fit_on_baseline(self, num_samples: int = 120) -> None:
        """Fit IsolationForest on a generated distribution of normal operating steps."""
        global _CACHED_BASELINE_MODEL
        if _CACHED_BASELINE_MODEL is not None:
            self.model = _CACHED_BASELINE_MODEL
            self.is_fitted = True
            return

        from app.simulator.warehouse import ColdStorageWarehouse

        wh = ColdStorageWarehouse(seed=self.random_state)
        samples = []
        for _ in range(num_samples):
            obs = wh.step()
            vec = [
                obs.temperature,
                obs.humidity,
                obs.inventory,
                obs.free_capacity,
                obs.inbound,
                obs.outbound,
                obs.occupancy,
            ]
            samples.append(vec)

        X_train = np.array(samples, dtype=float)
        self.model = IsolationForest(
            n_estimators=50,
            contamination=self.contamination,
            random_state=self.random_state,
        )
        self.model.fit(X_train)
        self.is_fitted = True
        _CACHED_BASELINE_MODEL = self.model
        logger.info(f"Fitted ML IsolationForest detector on {len(samples)} baseline observations.")

    def fit(self, observations: List[WarehouseObservation]) -> None:
        """Fit or refit the detector on a provided collection of normal observations."""
        if len(observations) < 10:
            raise ValueError("At least 10 observations required to train ML detector")

        X_train = np.vstack([self._extract_features(obs) for obs in observations])
        self.model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=self.random_state,
        )
        self.model.fit(X_train)
        self.is_fitted = True
        logger.info(f"Refitted ML detector on {len(observations)} observations.")

    def analyze(self, observation: WarehouseObservation) -> MLResult:
        """Analyze an observation and return a structured MLResult."""
        try:
            X = self._extract_features(observation)

            if not self.is_fitted or self.model is None:
                return self._fallback_analyze(observation)

            # IsolationForest decision_function: positive for inliers, negative for outliers
            raw_decision = float(self.model.decision_function(X)[0])

            # Monotonic mapping from decision_function to normalized anomaly score in [0.0, 1.0]
            # When decision > 0.15 (deep inlier), score -> ~0.05
            # When decision == 0.0 (boundary), score -> 0.50
            # When decision < -0.15 (outlier), score -> ~0.95
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
                features_evaluated=FEATURE_NAMES,
                details={
                    "raw_decision_function": round(raw_decision, 4),
                    "threshold": self.anomaly_threshold,
                    "model_type": "IsolationForest",
                },
            )

        except Exception as e:
            logger.error(f"ML analysis error: {e}. Utilizing fallback scoring.")
            return self._fallback_analyze(observation, str(e))

    def _fallback_analyze(self, observation: WarehouseObservation, error_msg: Optional[str] = None) -> MLResult:
        """Fallback boundary check if model inference fails."""
        anomaly_score = 0.0
        # Check extreme environmental drift
        if observation.temperature < settings.TEMP_MIN_BOUND or observation.temperature > settings.TEMP_MAX_BOUND:
            anomaly_score += 0.4
        if observation.humidity < settings.HUMIDITY_MIN_BOUND or observation.humidity > settings.HUMIDITY_MAX_BOUND:
            anomaly_score += 0.3
        anomaly_score = round(min(1.0, anomaly_score), 2)

        return MLResult(
            anomaly_score=anomaly_score,
            is_anomaly=anomaly_score >= self.anomaly_threshold,
            status="ANOMALY" if anomaly_score >= self.anomaly_threshold else "NORMAL",
            features_evaluated=FEATURE_NAMES,
            details={"fallback": True, "error": error_msg},
        )
