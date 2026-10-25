"""Temporal correlation and trend analysis engine.

Tracks observation history over a sliding window with exponential decay,
measuring persistence, recurrence, frequency, and escalation patterns over time.
"""

import collections
import logging
from typing import Deque, Dict, Any, Optional
from app.config import settings
from app.defender.models import TemporalResult, SemanticResult, MLResult, StructuralResult

logger = logging.getLogger("defender.temporal")


class TemporalEngine:
    """Evaluates time-series persistence, recurrence, and evidence decay across sequential observations."""

    def __init__(
        self,
        window_size: int = settings.TEMPORAL_WINDOW_SIZE,
        decay_factor: float = settings.TEMPORAL_DECAY_FACTOR,
    ):
        self.window_size = window_size
        self.decay_factor = decay_factor

        # Sliding window history of (step, semantic_score, ml_score, structural_score, is_violation)
        self.window: Deque[Dict[str, Any]] = collections.deque(maxlen=window_size)
        self.consecutive_violations = 0

    def update(
        self,
        step: int,
        semantic_result: Optional[SemanticResult] = None,
        ml_result: Optional[MLResult] = None,
        structural_result: Optional[StructuralResult] = None,
    ) -> TemporalResult:
        """Record observation outcomes and calculate updated temporal escalation metrics."""
        has_semantic_violation = bool(semantic_result and len(semantic_result.violated_constraints) > 0)
        has_env_warning = bool(
            semantic_result and any(
                c.constraint in ("C3", "C4") and c.status in ("VIOLATED", "WARNING")
                for c in semantic_result.constraints
            )
        )
        has_ml_anomaly = bool(ml_result and ml_result.is_anomaly)
        has_structural = bool(
            structural_result and structural_result.status in ("CORRELATED", "MULTI_SOURCE")
        )

        # Evidence-grounded violation indicator for temporal escalation:
        # 1. Deterministic invariant violations (C1/C2)
        # 2. Environmental envelope / spatial deviations (C3/C4)
        # 3. ML statistical anomaly corroborated by structural graph or high anomaly score
        is_violation = (
            has_semantic_violation
            or has_env_warning
            or (has_ml_anomaly and (has_structural or (ml_result and ml_result.anomaly_score >= 0.70)))
            or (has_structural and has_ml_anomaly)
        )

        # Update consecutive persistence
        if is_violation:
            self.consecutive_violations += 1
        else:
            self.consecutive_violations = 0

        sem_score = semantic_result.semantic_score if semantic_result else 0.0
        ml_score = ml_result.anomaly_score if ml_result else 0.0
        struct_score = structural_result.structural_score if structural_result else 0.0

        # Record into sliding window
        record = {
            "step": step,
            "semantic_score": sem_score,
            "ml_score": ml_score,
            "structural_score": struct_score,
            "is_violation": is_violation,
            "violated_constraints": semantic_result.violated_constraints if semantic_result else [],
        }
        self.window.append(record)

        # Calculate metrics over the sliding window
        n_records = len(self.window)
        if n_records == 0:
            return TemporalResult(
                temporal_score=0.0,
                status="STABLE",
                persistence=0,
                frequency=0.0,
                recurrence=0,
                window_size=self.window_size,
                explanation="No historical observations recorded in temporal window.",
            )

        recurrence = sum(1 for item in self.window if item["is_violation"])
        frequency = round(recurrence / n_records, 2)

        # Recency-weighted decay score: weight = decay_factor ** age
        weighted_sum = 0.0
        max_possible_weight = 0.0
        for i, item in enumerate(reversed(self.window)):
            weight = self.decay_factor ** i
            if item["is_violation"]:
                severity = max(item["semantic_score"], item["ml_score"], item.get("structural_score", 0.0))
                weighted_sum += weight * severity
            max_possible_weight += weight

        recency_weighted_score = weighted_sum / max_possible_weight if max_possible_weight > 0 else 0.0

        # Persistence bonus for consecutive sustained violations
        persistence_bonus = min(0.30, self.consecutive_violations * 0.10)
        temporal_score = round(min(1.0, recency_weighted_score + persistence_bonus), 2)

        # Classification of temporal state:
        # True escalation requires sustained persistence (>= 2) or high recurrence (>= 3)
        if self.consecutive_violations >= 3 or (self.consecutive_violations >= 2 and temporal_score >= 0.50) or recurrence >= 3:
            status = "ESCALATING"
            explanation = (
                f"ESCALATING THREAT: Persistent anomalies sustained over {self.consecutive_violations} consecutive steps "
                f"({recurrence}/{n_records} violations in window, decay score: {temporal_score:.2f})."
            )
        elif self.consecutive_violations >= 2 or recurrence >= 2:
            status = "ELEVATED"
            explanation = (
                f"ELEVATED RISK: Recurring anomalies observed ({recurrence}/{n_records} in window, "
                f"persistence: {self.consecutive_violations}, decay score: {temporal_score:.2f})."
            )
        else:
            status = "STABLE"
            explanation = (
                f"STABLE: Recent operations are consistent; decay score: {temporal_score:.2f}."
            )

        return TemporalResult(
            temporal_score=temporal_score,
            status=status,
            persistence=self.consecutive_violations,
            frequency=frequency,
            recurrence=recurrence,
            window_size=self.window_size,
            explanation=explanation,
        )

    def reset(self) -> None:
        """Clear temporal window and reset persistence counters."""
        self.window.clear()
        self.consecutive_violations = 0
        logger.info("Reset TemporalEngine sliding window and counters.")
