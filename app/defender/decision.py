"""Joint security decision engine combining multi-stage evidence.

Synthesizes ML anomaly scores, semantic constraint violations, temporal persistence,
and structural graph correlations into a final verified security classification.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from app.config import settings
from app.defender.models import (
    MLResult,
    SemanticResult,
    TemporalResult,
    StructuralResult,
    SecurityDecision,
)

logger = logging.getLogger("defender.decision")

# Fusion layers and the safety envelope for adaptive weights.  One layer may
# never silence another completely, and no layer may dominate without evidence.
FUSION_WEIGHT_KEYS = ("semantic", "temporal", "structural", "ml")
FUSION_WEIGHT_BOUNDS: Dict[str, tuple] = {
    "semantic": (0.20, 0.60),
    "temporal": (0.10, 0.40),
    "structural": (0.10, 0.40),
    "ml": (0.05, 0.35),
}


def validate_fusion_weights(weights: Dict[str, float]) -> Dict[str, float]:
    """Validate a complete fusion vector: finite, non-negative, bounded, sums to 1."""
    missing = [k for k in FUSION_WEIGHT_KEYS if k not in weights]
    if missing:
        raise ValueError(f"Missing fusion weights: {', '.join(missing)}")
    values = {}
    for key in FUSION_WEIGHT_KEYS:
        value = float(weights[key])
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError(f"Fusion weight '{key}' must be finite.")
        if value < 0.0:
            raise ValueError(f"Fusion weight '{key}' must be non-negative.")
        low, high = FUSION_WEIGHT_BOUNDS[key]
        if not (low - 1e-9 <= value <= high + 1e-9):
            raise ValueError(
                f"Fusion weight '{key}'={value:.3f} outside safety bounds [{low}, {high}]."
            )
        values[key] = value
    total = sum(values.values())
    if abs(total - 1.0) > 1e-5:
        raise ValueError(f"Fusion weights must sum to 1.0 (got {total:.6f}).")
    return values


class JointDecisionEngine:
    """Combines multi-stage defender evidence into a grounded security classification."""

    def __init__(
        self,
        weight_semantic: Optional[float] = None,
        weight_temporal: Optional[float] = None,
        weight_structural: Optional[float] = None,
        weight_ml: Optional[float] = None,
        primary_risk_threshold: Optional[float] = None,
        suspicious_risk_threshold: Optional[float] = None,
    ):
        self.w_semantic = (
            weight_semantic if weight_semantic is not None else getattr(settings, "DECISION_WEIGHT_SEMANTIC", 0.40)
        )
        self.w_temporal = (
            weight_temporal if weight_temporal is not None else getattr(settings, "DECISION_WEIGHT_TEMPORAL", 0.25)
        )
        self.w_structural = (
            weight_structural if weight_structural is not None else getattr(settings, "DECISION_WEIGHT_STRUCTURAL", 0.20)
        )
        self.w_ml = (
            weight_ml if weight_ml is not None else getattr(settings, "DECISION_WEIGHT_ML", 0.15)
        )
        self.primary_risk_threshold = (
            primary_risk_threshold if primary_risk_threshold is not None else getattr(settings, "DECISION_PRIMARY_RISK_THRESHOLD", 0.40)
        )
        self.suspicious_risk_threshold = (
            suspicious_risk_threshold if suspicious_risk_threshold is not None else getattr(settings, "DECISION_SUSPICIOUS_RISK_THRESHOLD", 0.20)
        )

    def get_weights(self) -> Dict[str, float]:
        """Return the active fusion weight vector."""
        return {
            "semantic": self.w_semantic,
            "temporal": self.w_temporal,
            "structural": self.w_structural,
            "ml": self.w_ml,
        }

    def update_weights(self, weights: Dict[str, float]) -> None:
        """Atomically replace fusion weights after safety validation.

        Callers must supply trusted, independently validated inputs.  This
        method deliberately accepts no packet, alert, or attacker feedback.
        """
        validated = validate_fusion_weights(weights)
        self.w_semantic = validated["semantic"]
        self.w_temporal = validated["temporal"]
        self.w_structural = validated["structural"]
        self.w_ml = validated["ml"]

    def decide(
        self,
        ml: Optional[MLResult] = None,
        semantic: Optional[SemanticResult] = None,
        temporal: Optional[TemporalResult] = None,
        structural: Optional[StructuralResult] = None,
    ) -> SecurityDecision:
        """Compute the joint security decision from stage outputs."""
        # 0. Gracefully handle missing or degraded layer outputs
        ml = ml or MLResult(anomaly_score=0.0, is_anomaly=False, status="NORMAL")
        semantic = semantic or SemanticResult(
            semantic_score=0.0,
            status="NORMAL",
            constraints=[],
            violated_constraints=[],
            evidence={},
            explanation="Semantic layer unavailable",
        )
        temporal = temporal or TemporalResult(
            temporal_score=0.0,
            persistence=0,
            frequency=0.0,
            recurrence=0,
            window_size=10,
            status="STABLE",
        )
        structural = structural or StructuralResult(
            structural_score=0.0,
            status="ISOLATED",
            affected_nodes=[],
            correlated_edges=[],
            explanation="Structural layer unavailable",
        )

        # 1. Compute weighted composite risk score in [0.0, 1.0]
        fused_risk = (
            self.w_semantic * semantic.semantic_score
            + self.w_temporal * temporal.temporal_score
            + self.w_structural * structural.structural_score
            + self.w_ml * ml.anomaly_score
        )
        risk_score = round(min(1.0, max(0.0, fused_risk)), 3)
        integrity_score = round(max(0.0, min(100.0, (1.0 - risk_score) * 100.0)), 1)

        # 2. Extract multi-layer evidence indicators
        has_semantic_violation = len(semantic.violated_constraints) > 0
        has_semantic_warning = any(c.status == "WARNING" for c in semantic.constraints)
        is_ml_anomalous = ml.is_anomaly or ml.anomaly_score >= 0.60
        is_temporally_escalated = temporal.status in ("ELEVATED", "ESCALATING")
        is_temporally_escalating = temporal.status == "ESCALATING"
        is_structurally_correlated = structural.status in ("CORRELATED", "MULTI_SOURCE")
        is_multi_source = structural.status == "MULTI_SOURCE"

        # 3. Rule-grounded deterministic classification
        # Tier 1: Coordinated Attack (multi-source cross-subsystem compromise with temporal escalation)
        if is_multi_source and is_temporally_escalated:
            classification = "COORDINATED_ATTACK"
            violation_info = f"Semantic violations ({', '.join(semantic.violated_constraints)}). " if has_semantic_violation else ""
            explanation = (
                f"COORDINATED ATTACK DETECTED: {violation_info}Multi-source structural compromise spanning multiple organizational subsystems "
                f"({', '.join(structural.affected_nodes)}) with persistent temporal escalation "
                f"(recurrence: {temporal.recurrence}, persistence: {temporal.persistence})."
            )

        # Tier 2: Primary Potential Attack
        # Pathway A: Deterministic hard semantic invariant violation (C1 or C2)
        elif has_semantic_violation:
            classification = "POTENTIAL_ATTACK"
            violation_reasons = [c.message for c in semantic.constraints if c.status == "VIOLATED"]
            explanation = (
                f"POTENTIAL DATA INTEGRITY ATTACK: Inconsistencies confirmed in operational records. "
                f"{' '.join(violation_reasons)}"
            )

        # Pathway B: Corroborated environmental attack (C3 breach with structural correlation & temporal escalation)
        elif has_semantic_warning and is_temporally_escalated and is_structurally_correlated:
            classification = "POTENTIAL_ATTACK"
            explanation = (
                f"POTENTIAL ENVIRONMENTAL SENSOR ATTACK: Operating conditions deviate from historical envelope "
                f"with structural correlation across ({', '.join(structural.affected_nodes)}) "
                f"and sustained temporal escalation (persistence: {temporal.persistence}, score: {temporal.temporal_score:.2f})."
            )

        # Pathway C: Multi-detector independent corroboration (ML anomaly + structural correlation + temporal escalation)
        elif is_ml_anomalous and is_temporally_escalating and is_structurally_correlated:
            classification = "POTENTIAL_ATTACK"
            explanation = (
                f"POTENTIAL MULTI-STAGE ATTACK: Statistical ML detector outlier (score: {ml.anomaly_score:.2f}) "
                f"corroborated by organizational graph correlation ({', '.join(structural.affected_nodes)}) "
                f"and escalating temporal persistence."
            )

        # Pathway D: High composite risk with temporal escalation and multi-layer corroboration
        elif risk_score >= self.primary_risk_threshold and is_temporally_escalated and (is_ml_anomalous or is_structurally_correlated):
            classification = "POTENTIAL_ATTACK"
            explanation = (
                f"POTENTIAL HIGH-RISK INCIDENT: Composite multi-stage risk score ({risk_score:.2f}) "
                f"exceeds primary alert threshold with confirmed temporal escalation."
            )

        # Tier 3: Suspicious / Triage Findings (investigation required, not primary alerts)
        elif has_semantic_warning:
            if is_ml_anomalous or is_temporally_escalated or is_structurally_correlated:
                classification = "SUSPICIOUS"
                explanation = (
                    f"SUSPICIOUS ACTIVITY: Operating conditions deviate from historical envelope "
                    f"with elevated temporal, ML (score: {ml.anomaly_score:.2f}), or structural markers."
                )
            else:
                classification = "LOW"
                explanation = (
                    f"LOW RISK: Environmental drift detected (Temp/Humidity) while operational "
                    f"inventory and capacity ledgers remain consistent."
                )

        elif is_ml_anomalous and (is_temporally_escalated or is_structurally_correlated or ml.anomaly_score >= 0.70):
            classification = "SUSPICIOUS"
            explanation = (
                f"SUSPICIOUS OBSERVATION: Statistical ML detector flagged an outlier "
                f"(score: {ml.anomaly_score:.2f}) with corroborating temporal or structural patterns."
            )

        elif temporal.status == "ESCALATING":
            classification = "SUSPICIOUS"
            explanation = (
                f"SUSPICIOUS (POST-INCIDENT): Current observation is consistent, but temporal "
                f"window reflects persistent recent violations (score: {temporal.temporal_score:.2f})."
            )

        elif risk_score >= self.suspicious_risk_threshold and (is_ml_anomalous or is_structurally_correlated or is_temporally_escalated):
            classification = "SUSPICIOUS"
            explanation = (
                f"SUSPICIOUS (ELEVATED RISK): Composite risk score ({risk_score:.2f}) warrants "
                f"triage investigation."
            )

        # Tier 4: Low Risk Findings
        elif is_ml_anomalous:
            classification = "LOW"
            explanation = (
                f"LOW RISK: Statistically unusual pattern detected by ML (score: {ml.anomaly_score:.2f}), "
                f"but all physical and semantic constraints pass."
            )

        elif temporal.status == "ELEVATED":
            classification = "LOW"
            explanation = (
                f"LOW (RECOVERY): Current observation is consistent; system in cooldown as recent "
                f"violation markers decay (score: {temporal.temporal_score:.2f})."
            )

        elif risk_score >= 0.15:
            classification = "LOW"
            explanation = f"LOW RISK: Minor residual telemetry deviation (risk score: {risk_score:.2f})."

        # Tier 5: Normal Operational State
        else:
            classification = "NORMAL"
            explanation = (
                f"NORMAL: Operational records, IoT telemetry, and shipment ledgers "
                f"are internally consistent and satisfy all integrity constraints."
            )

        contributing_evidence = {
            "fusion_weights": self.get_weights(),
            "ml": {
                "score": ml.anomaly_score,
                "status": ml.status,
                "is_anomaly": ml.is_anomaly,
            },
            "semantic": {
                "score": semantic.semantic_score,
                "status": semantic.status,
                "violated_constraints": semantic.violated_constraints,
            },
            "temporal": {
                "score": temporal.temporal_score,
                "status": temporal.status,
                "persistence": temporal.persistence,
                "recurrence": temporal.recurrence,
            },
            "structural": {
                "score": structural.structural_score,
                "status": structural.status,
                "affected_nodes": structural.affected_nodes,
            },
        }

        return SecurityDecision(
            classification=classification,
            risk_score=risk_score,
            integrity_score=integrity_score,
            contributing_evidence=contributing_evidence,
            explanation=explanation,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
