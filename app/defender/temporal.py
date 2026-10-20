"""Temporal analysis engine for stateful persistence, frequency, and decay tracking.

Aggregates observations across a sliding window to escalate recurring anomalies
and decay isolated or transient blips.
"""

import collections
import logging
from typing import Deque, Dict, Any, Optional
from app.config import settings
from app.defender.models import TemporalResult, SemanticResult, MLResult, StructuralResult

logger = logging.getLogger("defender.temporal")


class TemporalEngine:
    """Tracks time-series persistence, frequency, and decay of integrity violations."""

    def __init__(
        self,
        window_size: int = settings.TEMPORAL_WINDOW_SIZE,
        decay_factor: float = settings.TEMPORAL_DECAY_FACTOR,
    ):
        self.window_size = window_size
        self.decay_factor = decay_factor

        # Sliding window history of (step, semantic_score, ml_score, structural_score, has_violation)
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
        has_c3_warning = bool(
            semantic_result and any(c.constraint == "C3" and c.status in ("VIOLATED", "WARNING") for c in semantic_result.constraints)
        )
        has_ml_anomaly = bool(ml_result and ml_result.is_anomaly)
        has_structural = bool(
            structural_result and structural_result.status in ("CORRELATED", "MULTI_SOURCE")
        )

        # Evidence-grounded violation indicator for temporal escalation:
        # 1. Deterministic invariant violations (C1/C2)
        # 2. Environmental envelope deviations (C3)
        # 3. ML statistical anomaly at detector threshold corroborated by structural graph or high score
        is_violation = (
            has_semantic_violation
            or has_c3_warning
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
        total_in_window = len(self.window)
        if total_in_window == 0:
            return TemporalResult(
                temporal_score=0.0,
                persistence=0,
                frequency=0.0,
                recurrence=0,
                window_size=self.window_size,
                status="STABLE",
            )

        recurrence = sum(1 for r in self.window if r["is_violation"])
        frequency = round(recurrence / total_in_window, 2)

        # Recency-weighted decay: newest items have weight 1.0, older items scaled by decay_factor^k
        weighted_sum = 0.0
        max_possible_weight = 0.0
        # Iterate from most recent (index 0) backwards
        for i, item in enumerate(reversed(self.window)):
            weight = self.decay_factor ** i
            if item["is_violation"]:
                severity = max(item["semantic_score"], item["ml_score"], item.get("structural_score", 0.0))
                weighted_sum += weight * severity
            max_possible_weight += weight

        recency_weighted_score = (
            round(weighted_sum / max_possible_weight, 3) if max_possible_weight > 0 else 0.0
        )

        # Persistence amplifier: consecutive violations rapidly escalate the temporal score
        persistence_bonus = min(0.35, self.consecutive_violations * 0.10)

        temporal_score = round(min(1.0, recency_weighted_score + persistence_bonus), 2)

        # Classification of temporal state
        # True temporal escalation requires persistence (consecutive >= 2) or recurrence (recurrence >= 2)
        if self.consecutive_violations >= 3 or (self.consecutive_violations >= 2 and temporal_score >= 0.50) or recurrence >= 3:
            status = "ESCALATING"
        elif self.consecutive_violations >= 2 or recurrence >= 2:
            status = "ELEVATED"
        else:
            status = "STABLE"

        return TemporalResult(
            temporal_score=temporal_score,
            persistence=self.consecutive_violations,
            frequency=frequency,
            recurrence=recurrence,
            window_size=self.window_size,
            status=status,
            details={
                "recency_score": recency_weighted_score,
                "consecutive_steps": self.consecutive_violations,
                "recorded_steps": total_in_window,
            },
        )

    def reset(self) -> None:
        """Reset temporal state buffer."""
        self.window.clear()
        self.consecutive_violations = 0
