"""Data models and schemas for the Controlled Attack Experiment Engine."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ModifiedField(BaseModel):
    """Detailed record of a single modified sensor field."""

    sensor: str = Field(..., description="Target sensor identifier, e.g. SENSOR01")
    field: str = Field(..., description="Modified property, e.g. temperature or humidity")
    original_value: Optional[float] = Field(None, description="Original unmodified reading")
    modified_value: Optional[float] = Field(None, description="Injected attack reading")
    delta: Optional[float] = Field(None, description="Numerical offset applied")
    description: str = Field(..., description="Human-readable explanation of transformation")


class AttackConfiguration(BaseModel):
    """Configuration specification for a controlled attack injection."""

    scenario: str = Field(
        ...,
        description="Scenario identifier: temperature_manipulation, humidity_manipulation, sensor_drift, replay_substitution, cross_sensor_inconsistency, sensor_dropout",
    )
    target_sensor: str = Field(default="SENSOR01", description="Target sensor ID (SENSOR01-SENSOR09)")
    magnitude: Optional[float] = Field(default=None, description="Offset magnitude in deg C or % RH")
    drift_rate: Optional[float] = Field(default=None, description="Drift increment per step in deg C")
    drift_steps: Optional[int] = Field(default=None, description="Number of elapsed drift steps")
    replay_step: Optional[int] = Field(default=None, description="Discrete historical step to replay")
    seed: Optional[int] = Field(default=42, description="Random seed for deterministic replay")


class BaselineRunRequest(BaseModel):
    """Request payload to execute a normal baseline evaluation run."""

    step: int = Field(default=0, ge=0, description="Dataset observation step to evaluate as baseline")


class AttackExperimentRequest(BaseModel):
    """Request payload to execute a controlled attack injection experiment."""

    step: int = Field(default=0, ge=0, description="Dataset observation step to target")
    configuration: AttackConfiguration = Field(..., description="Attack injection parameters")


class ExperimentResult(BaseModel):
    """Immutable evaluation record linking injected truth, modified data, and Defender outputs."""

    experiment_id: str
    created_at: str
    step: int
    timestamp: str
    is_attack: bool
    attack_type: str
    target_sensor: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    modified_fields: List[ModifiedField] = Field(default_factory=list)
    expected_label: str  # NORMAL or ATTACK (Ground Truth - NOT passed to Defender!)
    defender_prediction: str  # NORMAL, SUSPICIOUS, POTENTIAL_ATTACK, COORDINATED_ATTACK
    outcome: str  # TRUE_POSITIVE, TRUE_NEGATIVE, FALSE_POSITIVE, FALSE_NEGATIVE
    detection_score: float  # Fused risk score
    integrity_score: float  # Data integrity fidelity
    detection_latency_ms: float
    contributing_layers: List[str] = Field(default_factory=list)
    explanation: str
    original_observation: Dict[str, Any]
    modified_observation: Dict[str, Any]
    security_analysis: Dict[str, Any]


class AggregateMetrics(BaseModel):
    """Empirical evaluation metrics computed across recorded experiment history."""

    total_experiments: int = 0
    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    false_positive_rate: Optional[float] = None
    accuracy: Optional[float] = None
    avg_latency_ms: float = 0.0
    per_attack_breakdown: Dict[str, Dict[str, Any]] = Field(default_factory=dict)


class ScenarioCatalogItem(BaseModel):
    """Metadata catalog entry for an available attack scenario."""

    id: str
    name: str
    description: str
    target_layers: List[str]
    default_parameters: Dict[str, Any]
    parameter_schema: Dict[str, Any]
