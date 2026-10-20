"""Pydantic data models for the defender security pipeline.

Defines serializable result schemas for ML anomaly detection, semantic verification,
temporal analysis, structural graph analysis, and joint security decisions.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.simulator.models import WarehouseObservation


class MLResult(BaseModel):
    """Result of statistical machine learning anomaly detection."""

    anomaly_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Normalized anomaly score from 0.0 (normal) to 1.0 (highly anomalous)",
    )
    is_anomaly: bool = Field(default=False, description="True if score exceeds detector threshold")
    status: str = Field(default="NORMAL", description="Status label: NORMAL, SUSPICIOUS, or ANOMALY")
    features_evaluated: List[str] = Field(default_factory=list, description="Names of features evaluated")
    details: Dict[str, Any] = Field(default_factory=dict, description="Diagnostic details or raw model output")


class ConstraintResult(BaseModel):
    """Result of an individual semantic constraint check (C1, C2, or C3)."""

    constraint: str = Field(..., description="Constraint identifier, e.g., 'C1', 'C2', 'C3'")
    name: str = Field(..., description="Human-readable constraint name")
    status: str = Field(default="PASSED", description="Status: PASSED, VIOLATED, or WARNING")
    expected: Any = Field(..., description="Expected value or range based on operational relationships")
    actual: Any = Field(..., description="Actual recorded observation value")
    difference: float = Field(default=0.0, description="Absolute discrepancy from expectation")
    tolerance: float = Field(default=0.0, description="Configured allowed tolerance")
    message: str = Field(..., description="Human-readable explanation of constraint outcome")


class SemanticResult(BaseModel):
    """Aggregated result of semantic integrity verification across all constraints."""

    semantic_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Normalized semantic violation score from 0.0 (clean) to 1.0 (severe)",
    )
    status: str = Field(default="NORMAL", description="Status: NORMAL, WARNING, or VIOLATION")
    constraints: List[ConstraintResult] = Field(default_factory=list, description="Individual constraint evaluations")
    violated_constraints: List[str] = Field(default_factory=list, description="List of violated constraint codes")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Structured numerical evidence")
    explanation: str = Field(default="All operational constraints satisfied.", description="Summary explanation")


class TemporalResult(BaseModel):
    """Result of temporal persistence, frequency, and recency analysis."""

    temporal_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Normalized temporal escalation score from 0.0 (stable) to 1.0 (severe escalation)",
    )
    persistence: int = Field(default=0, ge=0, description="Consecutive time steps with active violations")
    frequency: float = Field(default=0.0, ge=0.0, le=1.0, description="Violation frequency within sliding window")
    recurrence: int = Field(default=0, ge=0, description="Total violation occurrences within sliding window")
    window_size: int = Field(default=10, description="Number of historical steps evaluated")
    status: str = Field(default="STABLE", description="Status: STABLE, ELEVATED, or ESCALATING")
    details: Dict[str, Any] = Field(default_factory=dict, description="Detailed sliding window statistics")


class StructuralResult(BaseModel):
    """Result of structural graph analysis across organizational components."""

    structural_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Normalized structural correlation score from 0.0 (isolated) to 1.0 (multi-entity)",
    )
    status: str = Field(default="ISOLATED", description="Status: ISOLATED, CORRELATED, or MULTI_SOURCE")
    affected_nodes: List[str] = Field(default_factory=list, description="Organizational entities implicated")
    correlated_edges: List[List[str]] = Field(default_factory=list, description="Active relational dependencies")
    explanation: str = Field(default="No suspicious structural correlations detected.", description="Explanation")


class SecurityDecision(BaseModel):
    """Joint security decision synthesizing ML, semantic, temporal, and structural evidence."""

    classification: str = Field(
        default="NORMAL",
        description="Final classification: NORMAL, LOW, SUSPICIOUS, POTENTIAL_ATTACK, COORDINATED_ATTACK",
    )
    risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Combined risk probability from 0.0 (safe) to 1.0 (critical)",
    )
    integrity_score: float = Field(
        default=100.0,
        ge=0.0,
        le=100.0,
        description="Overall system integrity percentage from 0.0% to 100.0%",
    )
    contributing_evidence: Dict[str, Any] = Field(
        default_factory=dict,
        description="Scores and statuses from individual pipeline stages",
    )
    explanation: str = Field(..., description="Explanation of the security classification")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Timestamp of decision generation",
    )


class SecurityAlert(BaseModel):
    """Formal security alert generated when an attack or significant anomaly is detected."""

    alert_id: str = Field(..., description="Unique alert identifier")
    timestamp: str = Field(..., description="UTC ISO timestamp of alert creation")
    severity: str = Field(default="HIGH", description="Severity: LOW, MEDIUM, HIGH, CRITICAL")
    target: str = Field(default="Warehouse W01", description="Monitored entity or facility targeted")
    classification: str = Field(..., description="Associated security classification")
    reason: str = Field(..., description="Primary reason for alert trigger")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Evidence summary")
    resolved: bool = Field(default=False, description="True if alert has been acknowledged/resolved")


class SecurityEvent(BaseModel):
    """Audit event for the security event stream timeline with cryptographic SHA-256 chaining."""

    timestamp: str = Field(..., description="UTC ISO timestamp of event")
    step: int = Field(default=0, description="Simulation step number")
    event_type: str = Field(..., description="Event type identifier, e.g. DATA_RECEIVED, JOINT_DECISION")
    severity: str = Field(default="INFO", description="Severity: INFO, WARNING, ALERT, CRITICAL")
    source: str = Field(default="DefenderService", description="Source component")
    message: str = Field(..., description="Human-readable event description")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Auxiliary event metadata")
    prev_hash: str = Field(
        default="",
        description="SHA-256 hash of preceding event in the audit chain, or genesis hash",
    )
    event_hash: str = Field(
        default="",
        description="Cryptographic SHA-256 hash of canonical event payload including prev_hash",
    )

    def compute_hash(self) -> str:
        """Compute the canonical SHA-256 digest for this event payload."""
        from app.defender.audit import compute_event_hash
        return compute_event_hash(
            timestamp=self.timestamp,
            step=self.step,
            event_type=self.event_type,
            severity=self.severity,
            source=self.source,
            message=self.message,
            metadata=self.metadata,
            prev_hash=self.prev_hash,
        )

    def verify_hash(self) -> bool:
        """Verify that the stored event_hash matches the computed canonical hash."""
        import hmac
        if not self.event_hash:
            return False
        expected = self.compute_hash()
        return hmac.compare_digest(self.event_hash, expected)


class SecurityAnalysisResult(BaseModel):
    """Unified container representing the complete evaluation of a single observation."""

    warehouse: str = Field(default="W01")
    step: int = Field(default=0)
    timestamp: str = Field(...)
    observation: WarehouseObservation
    ml: MLResult
    semantic: SemanticResult
    temporal: TemporalResult
    structural: StructuralResult
    decision: SecurityDecision
    alerts: List[SecurityAlert] = Field(default_factory=list)

    def to_api_dict(self) -> Dict[str, Any]:
        """Format matching API_SPECIFICATION.md /api/security-analysis."""
        return {
            "warehouse": self.warehouse,
            "step": self.step,
            "timestamp": self.timestamp,
            "ml": self.ml.model_dump(),
            "semantic": self.semantic.model_dump(),
            "temporal": self.temporal.model_dump(),
            "structural": self.structural.model_dump(),
            "decision": self.decision.model_dump(),
        }
