"""Pydantic schemas for the FastAPI presentation and API layer."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.defender.audit import AuditChainVerificationResponse
from app.defender.hardening import (
    HardeningProposal,
    HardeningStatus,
    HardeningValidationResult,
    MissedAttackReport,
)
from app.defender.models import SecurityAlert, SecurityAnalysisResult, SecurityEvent
from app.simulator.models import WarehouseObservation


class HealthResponse(BaseModel):
    """Service health and component readiness response."""

    status: str = Field(default="healthy", description="Overall service operational health")
    service: str = Field(default="cold-storage-security-monitor", description="Service identifier")
    data_source: str = Field(default="hohenheim", description="Active data source provider")
    simulator: str = Field(default="standby", description="Status of the cold-storage simulator")
    defender: str = Field(default="ready", description="Status of the DefenderService pipeline")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="UTC timestamp of health check",
    )


class WarehouseStepResponse(BaseModel):
    """Response returned when the warehouse observation advances by one discrete step."""

    observation: WarehouseObservation = Field(..., description="Newly generated or replayed observation")
    security_analysis: SecurityAnalysisResult = Field(..., description="Actual security pipeline evaluation")


class WarehouseObservationHistoryItem(BaseModel):
    """Historical observation item for cold-storage operations."""

    step: int = Field(..., ge=0, description="Observation step number")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp")
    temperature: float = Field(..., description="Internal cold-storage temperature in °C")
    humidity: float = Field(..., description="Relative humidity percentage")
    inventory: Optional[float] = Field(default=None, description="Recorded inventory in metric tons (None if environmental data)")
    free_capacity: Optional[float] = Field(default=None, description="Available capacity in metric tons (None if environmental data)")
    total_capacity: Optional[float] = Field(default=None, description="Total storage capacity in metric tons (None if environmental data)")
    occupancy: Optional[float] = Field(default=None, description="Storage occupancy percentage (None if environmental data)")
    inbound: Optional[float] = Field(default=None, description="Inbound shipment tonnage (None if environmental data)")
    outbound: Optional[float] = Field(default=None, description="Outbound shipment tonnage (None if environmental data)")
    sensors: Optional[Dict[str, Dict[str, Optional[float]]]] = Field(default=None, description="Multi-sensor telemetry")
    active_action: Optional[str] = Field(default=None, description="Physical operational event (e.g. Door opened)")


class WarehouseHistoryResponse(BaseModel):
    """Collection of recent historical observations from cold-storage monitoring."""

    warehouse: str = Field(..., description="Warehouse identifier")
    observations: List[WarehouseObservationHistoryItem] = Field(..., description="List of historical observation records")


class PlaybackStatusResponse(BaseModel):
    """Current dataset playback state and progress."""

    source: str = Field(..., description="Data source name (hohenheim or simulator)")
    is_recorded_playback: bool = Field(..., description="True if playing back real recorded dataset")
    current_step: int = Field(..., description="Current observation step cursor")
    total_records: int = Field(..., description="Total observation steps available in dataset")
    progress_percent: Optional[float] = Field(default=None, description="Percentage of dataset completed")
    timestamp: Optional[str] = Field(default=None, description="Current observation timestamp")
    active_action: Optional[str] = Field(default=None, description="Active physical event (e.g. Door opened)")


class SeekPlaybackRequest(BaseModel):
    """Request payload to seek playback to a discrete step index."""

    step: int = Field(..., ge=0, description="Target playback step index")


class SecurityStatusResponse(BaseModel):
    """Overall organization security status summary."""

    status: str = Field(..., description="Classification: NORMAL, LOW, SUSPICIOUS, POTENTIAL_ATTACK, COORDINATED_ATTACK")
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Composite risk probability")
    integrity_score: float = Field(..., ge=0.0, le=100.0, description="System integrity percentage")
    active_alerts: int = Field(..., ge=0, description="Count of currently unresolved security alerts")
    sources: int = Field(default=9, description="Number of active organizational/IoT data sources")
    last_analysis_timestamp: Optional[str] = Field(None, description="Timestamp of latest security evaluation")
    backend_health: str = Field(default="ONLINE", description="Defender backend connectivity status")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="UTC timestamp of query",
    )


class ResetResponse(BaseModel):
    """Response returned upon system reset."""

    success: bool = Field(default=True)
    message: str = Field(default="Data source and DefenderService successfully reset to baseline.")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ScenarioInfo(BaseModel):
    """Metadata describing an available deterministic attack scenario."""

    id: str = Field(..., description="Scenario identifier used in API endpoints")
    name: str = Field(..., description="Human-readable scenario title")
    description: str = Field(..., description="Details of attack vector and affected operational parameters")
    target_constraint: str = Field(..., description="Primary constraint targeted (C1, C2, C3, Multi-Source)")


class ScenariosListResponse(BaseModel):
    """List of all registered deterministic attack scenarios."""

    scenarios: List[ScenarioInfo]


class ScenarioExecutionResponse(BaseModel):
    """Response returned after executing a deterministic attack scenario."""

    scenario: str = Field(..., description="Identifier of executed attack scenario")
    observation: WarehouseObservation = Field(..., description="Manipulated observation fed to defender")
    security_analysis: SecurityAnalysisResult = Field(..., description="Real pipeline analysis result")


# =====================================================================
# Attack Gateway Schemas (Part 1 <-> Part 2 Security Boundary)
# =====================================================================

ALLOWED_ATTACK_TYPES = {
    "capacity_manipulation",
    "inventory_manipulation",
    "sensor_spoofing",
    "replay_attack",
    "coordinated_weak",
    "multi_source",
}

ALLOWED_TARGETS_BY_TYPE = {
    "capacity_manipulation": {"free_capacity", "capacity"},
    "inventory_manipulation": {"inventory"},
    "sensor_spoofing": {"temperature", "humidity", "environmental_sensors"},
    "replay_attack": {"telemetry_stream", "state", "observation", "inventory"},
    "coordinated_weak": {"multi_metric", "inventory_and_capacity"},
    "multi_source": {"cross_subsystem", "facility", "multi_source"},
}


class AttackerObservationResponse(BaseModel):
    """Restricted operational observation response tailored for the external AI attacker."""

    target: str = Field(..., description="Target facility identifier (e.g., 'W01')")
    inventory: Optional[float] = Field(default=42.0, description="Reported inventory in metric tons")
    free_capacity: Optional[float] = Field(default=8.0, description="Reported free capacity in metric tons")
    temperature: float = Field(..., description="Internal warehouse temperature in °C")
    humidity: float = Field(..., description="Relative humidity percentage")
    occupancy: Optional[float] = Field(default=84.0, description="Warehouse occupancy percentage")

    model_config = ConfigDict(extra="forbid")


class AttackerAttackRequest(BaseModel):
    """Strict request schema for submitting a controlled attack request through the gateway."""

    attack_type: str = Field(..., description="Whitelisted attack type identifier")
    target: str = Field(..., description="Allowed target attribute or subsystem")
    value: Optional[float] = Field(default=None, description="Optional numerical manipulation parameter")
    objective: str = Field(..., min_length=1, description="Stated objective for audit logging")

    model_config = ConfigDict(extra="forbid")

    @field_validator("attack_type")
    @classmethod
    def validate_attack_type(cls, v: str) -> str:
        clean_type = v.strip().lower()
        if clean_type not in ALLOWED_ATTACK_TYPES:
            raise ValueError(
                f"Attack type '{v}' is not permitted. Whitelisted attack types: {sorted(list(ALLOWED_ATTACK_TYPES))}"
            )
        return clean_type

    @field_validator("target")
    @classmethod
    def validate_target_format(cls, v: str) -> str:
        clean_target = v.strip().lower()
        if not clean_target:
            raise ValueError("Target parameter must be a non-empty string.")
        return clean_target

    @model_validator(mode="after")
    def validate_target_matches_attack_type(self) -> "AttackerAttackRequest":
        allowed = ALLOWED_TARGETS_BY_TYPE.get(self.attack_type, set())
        if self.target not in allowed:
            raise ValueError(
                f"Target '{self.target}' is invalid for attack type '{self.attack_type}'. "
                f"Allowed targets: {sorted(list(allowed))}"
            )
        return self


class AttackerFeedbackResponse(BaseModel):
    """Restricted feedback returned to the external attacker after execution."""

    attack_id: str = Field(..., description="Unique sequential attack identifier")
    execution: str = Field(default="accepted", description="Execution status of the attack request")
    detection: str = Field(..., description="High-level detection outcome: 'DETECTED' or 'UNDETECTED'")
    classification: Optional[str] = Field(
        default=None,
        description="Security classification outcome (shielded unless explicitly configured)",
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="UTC timestamp of feedback generation",
    )

    model_config = ConfigDict(extra="forbid")


class AttackerResetResponse(BaseModel):
    """Response returned upon attacker environment reset."""

    success: bool = Field(default=True)
    message: str = Field(default="Simulator and DefenderService successfully reset to baseline.")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="UTC timestamp of reset",
    )

    model_config = ConfigDict(extra="forbid")


# =====================================================================
# Self-Hardening Purple-Team API Schemas
# =====================================================================


class HardeningProposalsListResponse(BaseModel):
    """List of all generated hardening proposals, active parameters, and recent misses."""

    status: HardeningStatus
    proposals: List[HardeningProposal]
    recent_misses: List[MissedAttackReport]


class HardeningApproveRequest(BaseModel):
    """Operator approval and activation request for a hardening proposal."""

    approved: bool = Field(default=True, description="Explicit operator approval confirmation")
    operator_name: str = Field(default="SecurityOperator", description="Identity of approving operator")


class HardeningApproveResponse(BaseModel):
    """Response returned upon approving and activating a hardening proposal."""

    success: bool = Field(default=True)
    proposal: HardeningProposal
    message: str


class HardeningRollbackResponse(BaseModel):
    """Response returned upon rolling back hardening adjustments."""

    success: bool = Field(default=True)
    message: str
    restored_parameters: Dict[str, Any]


# =====================================================================
# Sensor Transmitter to Defender Communication Schemas
# =====================================================================


class TransmitObservationRequest(BaseModel):
    """Payload to transmit an observation from Sensor Transmitter to the Defender."""

    step: Optional[int] = Field(default=None, ge=0, description="Step index to transmit. If omitted, uses active cursor.")
    observation: Optional[Dict[str, Any]] = Field(default=None, description="Explicit validated observation payload if provided.")


class TransmitObservationResponse(BaseModel):
    """Acknowledgement returned by the Defender to the Sensor Transmitter."""

    status: str = Field(default="DELIVERED", description="Transmission delivery state")
    observation_id: str = Field(..., description="Stable observation identifier")
    step: int = Field(..., ge=0, description="Dataset observation step transmitted")
    timestamp: str = Field(..., description="Observation timestamp")
    source: str = Field(..., description="Source dataset provenance identifier")
    sensors_transmitted: int = Field(..., description="Count of sensor channels in payload")
    active_sensors: int = Field(..., description="Count of online non-dropout sensors")
    defender_classification: str = Field(..., description="Defender joint classification verdict")
    risk_score: float = Field(..., description="Computed risk anomaly score")
    integrity_score: float = Field(..., description="Computed data integrity score")
    latency_ms: float = Field(..., description="Total transmission and inference benchmark latency in ms")
    security_analysis: SecurityAnalysisResult = Field(..., description="Full multi-layer analysis evidence")
