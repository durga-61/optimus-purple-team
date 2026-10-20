"""Defender service layer orchestrating the complete information security pipeline.

Independent of the presentation and API layer, this service ingests observations, executes
ML detection, evaluates semantic constraints, tracks temporal trends, performs structural
graph correlation, computes joint decisions, logs audit events, and manages security alerts.
"""

import collections
import logging
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional
import uuid

from app.config import settings
from app.defender.audit import (
    GENESIS_HASH,
    AuditChainVerificationResponse,
    compute_event_hash,
    verify_audit_chain,
)
from app.defender.decision import JointDecisionEngine
from app.defender.hardening import HardeningEngine
from app.defender.ml_detector import MLDetector
from app.defender.models import (
    SecurityAlert,
    SecurityAnalysisResult,
    SecurityDecision,
    SecurityEvent,
)
from app.defender.semantic import SemanticEngine
from app.defender.structural import StructuralEngine
from app.defender.temporal import TemporalEngine
from app.simulator.models import WarehouseObservation

logger = logging.getLogger("defender.service")


class DefenderService:
    """Orchestrates the multi-stage security pipeline for cold-storage data integrity."""

    def __init__(
        self,
        ml_detector: Optional[MLDetector] = None,
        semantic_engine: Optional[SemanticEngine] = None,
        temporal_engine: Optional[TemporalEngine] = None,
        structural_engine: Optional[StructuralEngine] = None,
        decision_engine: Optional[JointDecisionEngine] = None,
        history_size: int = settings.HISTORY_BUFFER_SIZE,
    ):
        self.ml_detector = ml_detector or MLDetector()
        self.semantic_engine = semantic_engine or SemanticEngine()
        self.temporal_engine = temporal_engine or TemporalEngine()
        self.structural_engine = structural_engine or StructuralEngine()
        self.decision_engine = decision_engine or JointDecisionEngine()

        self.history_size = history_size
        self.observation_history: Deque[WarehouseObservation] = collections.deque(maxlen=history_size)
        self.events: List[SecurityEvent] = []
        self.latest_event_hash: str = GENESIS_HASH
        self.alerts: List[SecurityAlert] = []
        self.last_observation: Optional[WarehouseObservation] = None
        self.latest_analysis: Optional[SecurityAnalysisResult] = None
        self.hardening_engine = HardeningEngine(service=self)

        logger.info("Initialized DefenderService pipeline with SHA-256 audit chaining and self-hardening loop.")

    def _log_event(
        self,
        event_type: str,
        severity: str,
        message: str,
        step: int,
        metadata: Optional[Dict] = None,
    ) -> SecurityEvent:
        """Internal helper to record an event to the audit stream with SHA-256 hash chaining."""
        timestamp = datetime.now(timezone.utc).isoformat()
        event_metadata = metadata or {}
        prev_hash = self.latest_event_hash

        event_hash = compute_event_hash(
            timestamp=timestamp,
            step=step,
            event_type=event_type,
            severity=severity,
            source="DefenderService",
            message=message,
            metadata=event_metadata,
            prev_hash=prev_hash,
        )

        event = SecurityEvent(
            timestamp=timestamp,
            step=step,
            event_type=event_type,
            severity=severity,
            source="DefenderService",
            message=message,
            metadata=event_metadata,
            prev_hash=prev_hash,
            event_hash=event_hash,
        )
        self.events.append(event)
        self.latest_event_hash = event_hash
        return event

    def analyze(self, observation: WarehouseObservation) -> SecurityAnalysisResult:
        """Process a single warehouse observation through the full security pipeline."""
        step = observation.step
        timestamp = observation.timestamp

        # 1. Ingestion Audit Event
        self._log_event(
            event_type="DATA_RECEIVED",
            severity="INFO",
            message=f"Received telemetry from {observation.warehouse} at step {step}.",
            step=step,
        )

        # 2. Replay & Sequence Freshness Check
        # Note on Replay Limitation: If a replay attack reuses past data but supplies
        # an incremented step counter, the sequence check will pass, but the sudden jump in
        # inventory will trigger C2 Inventory Flow violation. If an exact duplicate step is sent,
        # it is flagged here as a sequence anomaly.
        if self.last_observation is not None and observation.step <= self.last_observation.step:
            self._log_event(
                event_type="SEQUENCE_ANOMALY",
                severity="WARNING",
                message=(
                    f"Observation step ({observation.step}) is not strictly greater than "
                    f"prior step ({self.last_observation.step}). Potential replay or out-of-order ingestion."
                ),
                step=step,
            )

        # 3. Stage 1: ML Anomaly Detection
        ml_result = self.ml_detector.analyze(observation)
        self._log_event(
            event_type="ML_ANALYSIS_COMPLETED",
            severity="WARNING" if ml_result.is_anomaly else "INFO",
            message=f"ML analysis: status={ml_result.status}, score={ml_result.anomaly_score:.2f}.",
            step=step,
            metadata=ml_result.model_dump(),
        )

        # 4. Stage 2: Semantic Verification
        history_list = list(self.observation_history)
        semantic_result = self.semantic_engine.analyze(
            current_obs=observation,
            previous_obs=self.last_observation,
            history=history_list,
        )
        if semantic_result.violated_constraints:
            self._log_event(
                event_type="SEMANTIC_VIOLATION",
                severity="ALERT",
                message=f"Violations detected: {', '.join(semantic_result.violated_constraints)}.",
                step=step,
                metadata=semantic_result.model_dump(),
            )
        else:
            self._log_event(
                event_type="SEMANTIC_CHECK_PASSED",
                severity="INFO",
                message="All semantic constraints satisfied.",
                step=step,
            )

        # 5. Stage 3: Structural Analysis
        structural_result = self.structural_engine.analyze(
            semantic_result=semantic_result,
            ml_result=ml_result,
        )
        self._log_event(
            event_type="STRUCTURAL_ANALYSIS",
            severity="WARNING" if structural_result.status != "ISOLATED" else "INFO",
            message=(
                f"Structural correlation: {structural_result.status} "
                f"affecting {len(structural_result.affected_nodes)} entities."
            ),
            step=step,
        )

        # 6. Stage 4: Temporal Analysis
        temporal_result = self.temporal_engine.update(
            step=step,
            semantic_result=semantic_result,
            ml_result=ml_result,
            structural_result=structural_result,
        )
        self._log_event(
            event_type="TEMPORAL_ANALYSIS",
            severity="WARNING" if temporal_result.status != "STABLE" else "INFO",
            message=(
                f"Temporal state: {temporal_result.status} (persistence={temporal_result.persistence}, "
                f"recurrence={temporal_result.recurrence}, score={temporal_result.temporal_score:.2f})."
            ),
            step=step,
        )

        # 7. Stage 5: Joint Security Decision
        decision = self.decision_engine.decide(
            ml=ml_result,
            semantic=semantic_result,
            temporal=temporal_result,
            structural=structural_result,
        )
        self._log_event(
            event_type="JOINT_DECISION",
            severity="ALERT" if decision.classification in ("POTENTIAL_ATTACK", "COORDINATED_ATTACK") else "INFO",
            message=f"Classification: {decision.classification} (Integrity: {decision.integrity_score:.1f}%).",
            step=step,
            metadata=decision.model_dump(),
        )

        # 8. Alert Generation (for suspicious or attack states)
        current_alerts = []
        if decision.classification in ("POTENTIAL_ATTACK", "COORDINATED_ATTACK"):
            alert_severity = "CRITICAL" if decision.classification == "COORDINATED_ATTACK" else "HIGH"
            alert = SecurityAlert(
                alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                timestamp=datetime.now(timezone.utc).isoformat(),
                severity=alert_severity,
                target=f"Warehouse {observation.warehouse}",
                classification=decision.classification,
                reason=decision.explanation,
                evidence=decision.contributing_evidence,
            )
            self.alerts.append(alert)
            current_alerts.append(alert)
            self._log_event(
                event_type="ALERT_GENERATED",
                severity="CRITICAL",
                message=f"Active alert triggered: {alert.alert_id} ({alert.classification}).",
                step=step,
                metadata={"alert_id": alert.alert_id},
            )
        elif decision.classification == "SUSPICIOUS":
            self._log_event(
                event_type="TRIAGE_FINDING",
                severity="WARNING",
                message=f"Suspicious activity requiring triage: {decision.explanation}",
                step=step,
                metadata={"risk_score": decision.risk_score},
            )

        # 9. Commit state & history
        self.last_observation = observation
        self.observation_history.append(observation)

        analysis_result = SecurityAnalysisResult(
            warehouse=observation.warehouse,
            step=step,
            timestamp=timestamp,
            observation=observation,
            ml=ml_result,
            semantic=semantic_result,
            temporal=temporal_result,
            structural=structural_result,
            decision=decision,
            alerts=current_alerts,
        )
        self.latest_analysis = analysis_result
        return analysis_result

    def get_latest_analysis(self) -> Optional[SecurityAnalysisResult]:
        """Return the most recent analysis result."""
        return self.latest_analysis

    def get_events(self, limit: int = 50) -> List[SecurityEvent]:
        """Return the most recent security events up to limit."""
        events_list = list(self.events)
        if limit <= 0:
            return []
        return events_list[-limit:]

    def get_alerts(self, active_only: bool = True) -> List[SecurityAlert]:
        """Return security alerts."""
        if active_only:
            return [a for a in self.alerts if not a.resolved]
        return list(self.alerts)

    def get_status(self) -> Dict[str, Any]:
        """Summary status matching /api/status specification."""
        if self.latest_analysis is not None:
            status = self.latest_analysis.decision.classification
            integrity_score = self.latest_analysis.decision.integrity_score
        else:
            status = "NORMAL"
            integrity_score = 100.0

        active_alerts_count = len(self.get_alerts(active_only=True))

        return {
            "status": status,
            "integrity_score": integrity_score,
            "active_alerts": active_alerts_count,
            "sources": 5,  # Warehouse W01, Ledger, Sensors, Gateway, Historical profile
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def reset(self) -> None:
        """Reset service state, buffers, component engines, and audit chain root."""
        self.observation_history.clear()
        self.alerts.clear()
        self.last_observation = None
        self.latest_analysis = None
        self.temporal_engine.reset()
        self.hardening_engine.reset()
        self.events.clear()
        self.latest_event_hash = GENESIS_HASH
        logger.info("Reset DefenderService state and audit chain root.")

    def verify_audit_chain(self) -> AuditChainVerificationResponse:
        """Cryptographically verify the in-memory security event audit chain.

        Verifies that every event has a valid SHA-256 payload digest and that
        the sequence from GENESIS_HASH to latest_event_hash is unbroken.
        """
        return verify_audit_chain(self.events, genesis_hash=GENESIS_HASH)
