"""Miss-Driven Self-Hardening Purple-Team Engine.

This module implements the closed-loop hardening mechanism that:
1. Ingests confirmed missed attacks and captures multi-layer detector evidence.
2. Diagnoses the root failure cause (e.g. semantic tolerance slack, envelope gap, risk threshold).
3. Generates candidate defensive adjustments bounded by strict safety envelopes.
4. Validates proposals against an independent validation dataset containing both normal and attack samples.
5. Rejects proposals that cause false-positive regressions or fail to improve detection.
6. Enforces an explicit human operator approval gate before activating any adjustment in production.
7. Dispatches all lifecycle events (miss recorded, proposal generated, validated, rejected, approved,
   activated, rolled back) through the SHA-256 cryptographic audit chain.
8. Preserves the original baseline configuration and provides one-click rollback and clean reset.
"""

from copy import deepcopy
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple
import uuid

from pydantic import BaseModel, Field

from app.config import settings
from app.simulator.models import WarehouseObservation

logger = logging.getLogger("defender.hardening")

PARAMETER_BOUNDS: Dict[str, Tuple[float, float]] = {
    "c1_tolerance": (0.10, 0.50),
    "c2_tolerance": (0.10, 0.50),
    "primary_risk_threshold": (0.25, 0.50),
    "suspicious_risk_threshold": (0.10, 0.30),
}


class MissedAttackReport(BaseModel):
    """Structured record of a confirmed attack that bypassed primary alert detection."""

    miss_id: str = Field(default_factory=lambda: f"MISS-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    step: int = Field(default=0)
    attack_type: str = Field(..., description="Ground-truth attack classification")
    target: Optional[str] = Field(default=None, description="Targeted subsystem or variable")
    injected_value: Optional[float] = Field(default=None, description="Injected perturbation value")
    observation: Dict[str, Any] = Field(default_factory=dict, description="Warehouse observation telemetry")
    detector_evidence: Dict[str, Any] = Field(default_factory=dict, description="Contributing detector evidence")
    diagnosed_cause: str = Field(..., description="Root cause diagnosed by hardening engine")
    details: str = Field(default="", description="Detailed human-readable diagnostic summary")


class HardeningValidationResult(BaseModel):
    """Validation report benchmarking a candidate proposal on a separate validation dataset."""

    validated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    samples_evaluated: int = Field(default=0)
    normal_samples: int = Field(default=0)
    attack_samples: int = Field(default=0)
    baseline_recall: float = Field(default=0.0)
    candidate_recall: float = Field(default=0.0)
    recall_delta: float = Field(default=0.0)
    baseline_fpr: float = Field(default=0.0)
    candidate_fpr: float = Field(default=0.0)
    fpr_delta: float = Field(default=0.0)
    baseline_f1: float = Field(default=0.0)
    candidate_f1: float = Field(default=0.0)
    f1_delta: float = Field(default=0.0)
    max_allowed_fpr: float = Field(default=0.001)
    passed_fpr_limit: bool = Field(default=False)
    improved_objective: bool = Field(default=False)
    verdict: str = Field(default="REJECTED", description="'PASSED' or 'REJECTED'")
    rejection_reason: Optional[str] = Field(default=None)


class HardeningProposal(BaseModel):
    """A proposed bounded defensive adjustment generated in response to missed attacks."""

    proposal_id: str = Field(default_factory=lambda: f"PROP-{uuid.uuid4().hex[:8].upper()}")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    trigger_miss_id: str = Field(..., description="Identifier of the triggering missed attack")
    adjustment_type: str = Field(
        default="TOLERANCE_TIGHTENING",
        description="Type: TOLERANCE_TIGHTENING, THRESHOLD_ADJUSTMENT, or INVARIANT_RULE",
    )
    target_parameter: str = Field(
        ...,
        description="Target parameter name (e.g. c1_tolerance, c2_tolerance, primary_risk_threshold)",
    )
    current_value: float = Field(...)
    proposed_value: float = Field(...)
    parameter_bounds: Tuple[float, float] = Field(...)
    rationale: str = Field(...)
    status: str = Field(
        default="PENDING_VALIDATION",
        description="PENDING_VALIDATION, VALIDATED, REJECTED, PENDING_APPROVAL, APPROVED, ACTIVE, ROLLED_BACK",
    )
    validation_result: Optional[HardeningValidationResult] = None
    operator_approved: bool = Field(default=False)
    approved_by: Optional[str] = None
    approval_timestamp: Optional[str] = None
    activated_at: Optional[str] = None
    rolled_back_at: Optional[str] = None


class HardeningStatus(BaseModel):
    """High-level status summary of the self-hardening engine."""

    active_proposals_count: int = 0
    pending_proposals_count: int = 0
    rejected_proposals_count: int = 0
    missed_attacks_recorded: int = 0
    active_parameters: Dict[str, Any] = Field(default_factory=dict)
    baseline_parameters: Dict[str, Any] = Field(default_factory=dict)
    is_hardened: bool = False


class HardeningEngine:
    """Orchestrates miss capture, root-cause diagnosis, proposal generation, validation, approval, and rollback."""

    def __init__(self, service: Optional[Any] = None):
        self.service = service
        self.missed_attacks: List[MissedAttackReport] = []
        self.proposals: Dict[str, HardeningProposal] = {}
        self.active_proposal_ids: List[str] = []

        # Store baseline parameters from configuration
        self.baseline_config: Dict[str, float] = {
            "c1_tolerance": float(settings.C1_CAPACITY_TOLERANCE),
            "c2_tolerance": float(settings.C2_FLOW_TOLERANCE),
            "primary_risk_threshold": float(settings.DECISION_PRIMARY_RISK_THRESHOLD),
            "suspicious_risk_threshold": float(settings.DECISION_SUSPICIOUS_RISK_THRESHOLD),
        }
        self.current_parameters: Dict[str, float] = dict(self.baseline_config)

        logger.info(
            f"Initialized HardeningEngine with baseline parameters: {self.baseline_config}"
        )

    def _log_audit_event(
        self,
        event_type: str,
        severity: str,
        message: str,
        step: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Helper to dispatch hardening lifecycle events into the SHA-256 audit chain."""
        if self.service is not None and hasattr(self.service, "_log_event"):
            self.service._log_event(
                event_type=event_type,
                severity=severity,
                message=message,
                step=step,
                metadata=metadata or {},
            )
        else:
            logger.info(f"[{event_type}] ({severity}) {message} | metadata={metadata}")

    def record_miss(
        self,
        observation: WarehouseObservation,
        analysis: Optional[Any] = None,
        attack_type: str = "unknown",
        target: Optional[str] = None,
        value: Optional[float] = None,
        step: Optional[int] = None,
    ) -> MissedAttackReport:
        """Record confirmed missed attack, extract detector evidence, and diagnose cause."""
        obs_step = step if step is not None else observation.step
        obs_dict = observation.model_dump()

        # Extract evidence from multi-stage analysis
        evidence: Dict[str, Any] = {}
        if analysis is not None:
            if hasattr(analysis, "decision"):
                evidence["classification"] = analysis.decision.classification
                evidence["risk_score"] = analysis.decision.risk_score
                evidence["integrity_score"] = analysis.decision.integrity_score
            if hasattr(analysis, "ml"):
                evidence["ml_score"] = analysis.ml.anomaly_score
                evidence["ml_is_anomaly"] = analysis.ml.is_anomaly
            if hasattr(analysis, "semantic"):
                evidence["semantic_score"] = analysis.semantic.semantic_score
                evidence["violated_constraints"] = analysis.semantic.violated_constraints
                evidence["c1_diff"] = analysis.semantic.evidence.get("c1_difference", 0.0)
                evidence["c2_diff"] = analysis.semantic.evidence.get("c2_difference", 0.0)
            if hasattr(analysis, "temporal"):
                evidence["temporal_score"] = analysis.temporal.temporal_score
                evidence["temporal_status"] = analysis.temporal.status
            if hasattr(analysis, "structural"):
                evidence["structural_score"] = analysis.structural.structural_score
                evidence["structural_status"] = analysis.structural.status
        else:
            # Fallback manual extraction
            c1_calc = round(abs((observation.inventory + observation.free_capacity) - observation.capacity), 2)
            evidence["c1_diff"] = c1_calc
            evidence["classification"] = "NORMAL"
            evidence["risk_score"] = 0.0

        # Perform root-cause diagnosis
        cause, details = self.diagnose_cause(
            observation=observation,
            evidence=evidence,
            attack_type=attack_type,
        )

        miss_report = MissedAttackReport(
            step=obs_step,
            attack_type=attack_type,
            target=target,
            injected_value=value,
            observation=obs_dict,
            detector_evidence=evidence,
            diagnosed_cause=cause,
            details=details,
        )
        self.missed_attacks.append(miss_report)

        self._log_audit_event(
            event_type="HARDENING_MISS_RECORDED",
            severity="WARNING",
            message=(
                f"Missed attack recorded: {miss_report.miss_id} (type='{attack_type}', "
                f"cause='{cause}', step={obs_step})."
            ),
            step=obs_step,
            metadata={
                "miss_id": miss_report.miss_id,
                "attack_type": attack_type,
                "diagnosed_cause": cause,
                "evidence": evidence,
            },
        )

        return miss_report

    def diagnose_cause(
        self,
        observation: WarehouseObservation,
        evidence: Dict[str, Any],
        attack_type: str,
    ) -> Tuple[str, str]:
        """Diagnose why an attack bypassed the multi-layer detector pipeline."""
        c1_diff = float(evidence.get("c1_diff", 0.0))
        c2_diff = float(evidence.get("c2_diff", 0.0))
        risk_score = float(evidence.get("risk_score", 0.0))
        current_c1_tol = self.current_parameters["c1_tolerance"]
        current_c2_tol = self.current_parameters["c2_tolerance"]
        current_risk_thresh = self.current_parameters["primary_risk_threshold"]

        # Check C1 capacity invariant discrepancy
        if c1_diff > 0.0 and c1_diff <= current_c1_tol:
            cause = "STEALTHY_CAPACITY_SLACK_BELOW_C1_TOLERANCE"
            details = (
                f"Capacity balance discrepancy of {c1_diff:.2f}t evaded C1 constraint because it is "
                f"within current c1_tolerance of {current_c1_tol:.2f}t."
            )
            return cause, details

        # Check C2 inventory flow discrepancy
        if c2_diff > 0.0 and c2_diff <= current_c2_tol:
            cause = "STEALTHY_FLOW_DISCREPANCY_BELOW_C2_TOLERANCE"
            details = (
                f"Inventory flow discrepancy of {c2_diff:.2f}t evaded C2 constraint because it is "
                f"within current c2_tolerance of {current_c2_tol:.2f}t."
            )
            return cause, details

        # Check coordinated weak attack pattern
        if attack_type == "coordinated_weak":
            calc_diff = round(abs((observation.inventory + observation.free_capacity) - observation.capacity), 2)
            if calc_diff > 0.0 and calc_diff <= current_c1_tol:
                cause = "STEALTHY_CAPACITY_SLACK_BELOW_C1_TOLERANCE"
                details = (
                    f"Coordinated weak attack shifted inventory and capacity by opposite amounts, "
                    f"leaving a net discrepancy of {calc_diff:.2f}t beneath c1_tolerance ({current_c1_tol:.2f}t)."
                )
                return cause, details

        # Check composite risk score near threshold
        if risk_score >= 0.20 and risk_score < current_risk_thresh:
            cause = "COMPOSITE_RISK_BELOW_PRIMARY_THRESHOLD"
            details = (
                f"Composite risk score ({risk_score:.2f}) was elevated but remained beneath the "
                f"primary alert threshold ({current_risk_thresh:.2f})."
            )
            return cause, details

        # Default fallback
        cause = "MULTI_STAGE_CORROBORATION_GAP"
        details = (
            f"Attack of type '{attack_type}' did not breach individual semantic tolerances or produce "
            f"sufficient corroboration across ML and temporal layers."
        )
        return cause, details

    def generate_proposal(
        self,
        miss_report: MissedAttackReport,
        target_parameter: Optional[str] = None,
        override_value: Optional[float] = None,
    ) -> Optional[HardeningProposal]:
        """Generate a bounded candidate defensive adjustment proposal from a missed attack report."""
        cause = miss_report.diagnosed_cause
        c1_diff = float(miss_report.detector_evidence.get("c1_diff", 0.0))
        c2_diff = float(miss_report.detector_evidence.get("c2_diff", 0.0))
        risk_score = float(miss_report.detector_evidence.get("risk_score", 0.0))

        param = target_parameter
        proposed_val: float

        if param is None:
            if cause == "STEALTHY_CAPACITY_SLACK_BELOW_C1_TOLERANCE":
                param = "c1_tolerance"
                current_val = self.current_parameters["c1_tolerance"]
                target_diff = c1_diff if c1_diff > 0.0 else 0.50
                # Tighten tolerance to 80% of observed discrepancy, bounded
                proposed_val = max(0.10, round(target_diff * 0.8, 2))
                if proposed_val >= current_val:
                    proposed_val = max(0.10, round(current_val - 0.10, 2))
                adj_type = "TOLERANCE_TIGHTENING"
                rationale = (
                    f"Tighten C1 capacity tolerance from {current_val:.2f}t to {proposed_val:.2f}t to "
                    f"close observed evasion slack of {target_diff:.2f}t."
                )

            elif cause == "STEALTHY_FLOW_DISCREPANCY_BELOW_C2_TOLERANCE":
                param = "c2_tolerance"
                current_val = self.current_parameters["c2_tolerance"]
                target_diff = c2_diff if c2_diff > 0.0 else 0.50
                proposed_val = max(0.10, round(target_diff * 0.8, 2))
                if proposed_val >= current_val:
                    proposed_val = max(0.10, round(current_val - 0.10, 2))
                adj_type = "TOLERANCE_TIGHTENING"
                rationale = (
                    f"Tighten C2 inventory flow tolerance from {current_val:.2f}t to {proposed_val:.2f}t to "
                    f"close observed flow discrepancy slack of {target_diff:.2f}t."
                )

            elif cause == "COMPOSITE_RISK_BELOW_PRIMARY_THRESHOLD":
                param = "primary_risk_threshold"
                current_val = self.current_parameters["primary_risk_threshold"]
                proposed_val = max(0.25, round(risk_score * 0.95, 2))
                if proposed_val >= current_val:
                    proposed_val = max(0.25, round(current_val - 0.05, 2))
                adj_type = "THRESHOLD_ADJUSTMENT"
                rationale = (
                    f"Adjust primary alert decision threshold from {current_val:.2f} to {proposed_val:.2f} "
                    f"to detect corroborated events with risk score {risk_score:.2f}."
                )

            else:
                # Default fallback for stealth attacks: tighten C1 tolerance
                param = "c1_tolerance"
                current_val = self.current_parameters["c1_tolerance"]
                proposed_val = max(0.10, round(current_val * 0.80, 2))
                adj_type = "TOLERANCE_TIGHTENING"
                rationale = (
                    f"Propose bounded tightening of C1 tolerance from {current_val:.2f}t to {proposed_val:.2f}t."
                )
        else:
            current_val = self.current_parameters.get(param, 0.50)
            proposed_val = override_value if override_value is not None else max(0.10, round(current_val * 0.8, 2))
            adj_type = "TOLERANCE_TIGHTENING" if "tolerance" in param else "THRESHOLD_ADJUSTMENT"
            rationale = f"Manual adjustment proposed for parameter '{param}'."

        if override_value is not None:
            proposed_val = override_value

        # Enforce safety bounds
        min_b, max_b = PARAMETER_BOUNDS.get(param, (0.10, 0.50))
        clamped_val = max(min_b, min(max_b, proposed_val))
        proposed_val = round(clamped_val, 3)

        proposal = HardeningProposal(
            trigger_miss_id=miss_report.miss_id,
            adjustment_type=adj_type,
            target_parameter=param,
            current_value=float(current_val),
            proposed_value=float(proposed_val),
            parameter_bounds=(min_b, max_b),
            rationale=rationale,
            status="PENDING_VALIDATION",
        )
        self.proposals[proposal.proposal_id] = proposal

        self._log_audit_event(
            event_type="HARDENING_PROPOSAL_GENERATED",
            severity="INFO",
            message=(
                f"Generated hardening proposal {proposal.proposal_id}: "
                f"parameter='{param}', {current_val} -> {proposed_val}."
            ),
            step=miss_report.step,
            metadata={
                "proposal_id": proposal.proposal_id,
                "trigger_miss_id": miss_report.miss_id,
                "target_parameter": param,
                "current_value": current_val,
                "proposed_value": proposed_val,
            },
        )

        return proposal

    def validate_proposal(
        self,
        proposal: HardeningProposal,
        validation_records: Optional[List[Any]] = None,
        max_allowed_fpr: float = 0.001,
        max_samples: Optional[int] = None,
    ) -> HardeningValidationResult:
        """Validate candidate proposal against a separate validation dataset containing normal and attack observations.

        Rejection Criteria:
        1. candidate_fpr > max_allowed_fpr (violates false-positive limit)
        2. candidate_fpr > baseline_fpr + 1e-5 (causes false-positive regression)
        3. candidate_recall <= baseline_recall and candidate_f1 <= baseline_f1 (fails to improve detection objective)
        """
        # Load validation records if not passed explicitly
        if validation_records is None:
            try:
                from app.evaluation.dataset import (
                    generate_normal_dataset,
                    generate_attack_dataset,
                    create_temporal_splits,
                )
                normals = generate_normal_dataset(num_samples=2000, seed=42)
                attacks = generate_attack_dataset(num_samples_per_class=400, seed=42)
                splits = create_temporal_splits(normals, attacks, val_ratio=0.25, test_ratio=0.25)
                eval_records = splits.val
            except Exception as e:
                logger.error(f"Failed to load standard validation split: {e}")
                eval_records = []
        else:
            eval_records = list(validation_records)

        if max_samples is not None and len(eval_records) > max_samples:
            # Stratified sub-sample: keep balanced normal and attack records
            normals = [r for r in eval_records if r.ground_truth_label == 0]
            attacks = [r for r in eval_records if r.ground_truth_label == 1]
            half = max_samples // 2
            eval_records = normals[:half] + attacks[:half]

        total_samples = len(eval_records)
        if total_samples == 0:
            result = HardeningValidationResult(
                samples_evaluated=0,
                verdict="REJECTED",
                rejection_reason="No validation records available for evaluation.",
            )
            proposal.status = "REJECTED"
            proposal.validation_result = result
            return result

        normal_count = sum(1 for r in eval_records if r.ground_truth_label == 0)
        attack_count = sum(1 for r in eval_records if r.ground_truth_label == 1)

        # 1. Evaluate baseline pipeline on validation records
        baseline_tp, baseline_fp, baseline_tn, baseline_fn = self._evaluate_split(
            records=eval_records,
            param_overrides=self.current_parameters,
        )

        baseline_recall = baseline_tp / (baseline_tp + baseline_fn) if (baseline_tp + baseline_fn) > 0 else 0.0
        baseline_fpr = baseline_fp / (baseline_fp + baseline_tn) if (baseline_fp + baseline_tn) > 0 else 0.0
        baseline_prec = baseline_tp / (baseline_tp + baseline_fp) if (baseline_tp + baseline_fp) > 0 else 1.0
        baseline_f1 = (
            (2.0 * baseline_prec * baseline_recall) / (baseline_prec + baseline_recall)
            if (baseline_prec + baseline_recall) > 0
            else 0.0
        )

        # 2. Evaluate candidate pipeline with proposed adjustment tentatively applied
        candidate_params = dict(self.current_parameters)
        candidate_params[proposal.target_parameter] = proposal.proposed_value

        candidate_tp, candidate_fp, candidate_tn, candidate_fn = self._evaluate_split(
            records=eval_records,
            param_overrides=candidate_params,
        )

        candidate_recall = candidate_tp / (candidate_tp + candidate_fn) if (candidate_tp + candidate_fn) > 0 else 0.0
        candidate_fpr = candidate_fp / (candidate_fp + candidate_tn) if (candidate_fp + candidate_tn) > 0 else 0.0
        candidate_prec = candidate_tp / (candidate_tp + candidate_fp) if (candidate_tp + candidate_fp) > 0 else 1.0
        candidate_f1 = (
            (2.0 * candidate_prec * candidate_recall) / (candidate_prec + candidate_recall)
            if (candidate_prec + candidate_recall) > 0
            else 0.0
        )

        recall_delta = round(candidate_recall - baseline_recall, 4)
        fpr_delta = round(candidate_fpr - baseline_fpr, 4)
        f1_delta = round(candidate_f1 - baseline_f1, 4)

        # Evaluation criteria checks
        passed_fpr = (candidate_fpr <= max_allowed_fpr) and (candidate_fpr <= baseline_fpr + 1e-5)
        improved_objective = (candidate_recall > baseline_recall + 1e-4) or (candidate_f1 > baseline_f1 + 1e-4)

        if not passed_fpr:
            verdict = "REJECTED"
            rejection_reason = (
                f"False-positive regression: candidate FPR ({candidate_fpr:.4f}) exceeds "
                f"limit ({max_allowed_fpr:.4f}) or baseline FPR ({baseline_fpr:.4f})."
            )
            proposal.status = "REJECTED"
        elif not improved_objective:
            verdict = "REJECTED"
            rejection_reason = (
                f"Failed to improve objective: candidate recall ({candidate_recall:.4f}) <= baseline ({baseline_recall:.4f}) "
                f"and candidate F1 ({candidate_f1:.4f}) <= baseline ({baseline_f1:.4f})."
            )
            proposal.status = "REJECTED"
        else:
            verdict = "PASSED"
            rejection_reason = None
            proposal.status = "PENDING_APPROVAL"

        validation_result = HardeningValidationResult(
            samples_evaluated=total_samples,
            normal_samples=normal_count,
            attack_samples=attack_count,
            baseline_recall=round(baseline_recall, 4),
            candidate_recall=round(candidate_recall, 4),
            recall_delta=recall_delta,
            baseline_fpr=round(baseline_fpr, 4),
            candidate_fpr=round(candidate_fpr, 4),
            fpr_delta=fpr_delta,
            baseline_f1=round(baseline_f1, 4),
            candidate_f1=round(candidate_f1, 4),
            f1_delta=f1_delta,
            max_allowed_fpr=max_allowed_fpr,
            passed_fpr_limit=passed_fpr,
            improved_objective=improved_objective,
            verdict=verdict,
            rejection_reason=rejection_reason,
        )
        proposal.validation_result = validation_result

        # Audit event dispatching
        if verdict == "PASSED":
            self._log_audit_event(
                event_type="HARDENING_PROPOSAL_VALIDATED",
                severity="INFO",
                message=(
                    f"Hardening proposal {proposal.proposal_id} validated successfully "
                    f"(Recall: {baseline_recall:.2%} -> {candidate_recall:.2%}, FPR: {candidate_fpr:.4f})."
                ),
                metadata={
                    "proposal_id": proposal.proposal_id,
                    "target_parameter": proposal.target_parameter,
                    "validation_result": validation_result.model_dump(),
                },
            )
        else:
            self._log_audit_event(
                event_type="HARDENING_PROPOSAL_REJECTED",
                severity="WARNING",
                message=f"Hardening proposal {proposal.proposal_id} rejected: {rejection_reason}",
                metadata={
                    "proposal_id": proposal.proposal_id,
                    "target_parameter": proposal.target_parameter,
                    "rejection_reason": rejection_reason,
                    "validation_result": validation_result.model_dump(),
                },
            )

        return validation_result

    def _evaluate_split(
        self,
        records: List[Any],
        param_overrides: Dict[str, float],
    ) -> Tuple[int, int, int, int]:
        """Run an isolated pipeline evaluation on a set of EvaluationRecords using overridden parameters."""
        from app.defender.decision import JointDecisionEngine
        from app.defender.semantic import SemanticEngine
        from app.defender.structural import StructuralEngine
        from app.defender.temporal import TemporalEngine

        sem = SemanticEngine(
            c1_tolerance=param_overrides.get("c1_tolerance", settings.C1_CAPACITY_TOLERANCE),
            c2_tolerance=param_overrides.get("c2_tolerance", settings.C2_FLOW_TOLERANCE),
        )
        temp = TemporalEngine()
        struct = StructuralEngine()
        dec = JointDecisionEngine(
            primary_risk_threshold=param_overrides.get(
                "primary_risk_threshold", settings.DECISION_PRIMARY_RISK_THRESHOLD
            ),
            suspicious_risk_threshold=param_overrides.get(
                "suspicious_risk_threshold", settings.DECISION_SUSPICIOUS_RISK_THRESHOLD
            ),
        )

        tp, fp, tn, fn = 0, 0, 0, 0
        last_obs = None
        history_list: List[WarehouseObservation] = []

        for record in records:
            obs = record.get_inference_observation() if hasattr(record, "get_inference_observation") else record.observation
            label = record.ground_truth_label

            sem_res = sem.analyze(current_obs=obs, previous_obs=last_obs, history=history_list)
            # MLResult stub or inference
            from app.defender.models import MLResult
            ml_res = MLResult(anomaly_score=0.0, is_anomaly=False, status="NORMAL")

            struct_res = struct.analyze(semantic_result=sem_res, ml_result=ml_res)
            temp_res = temp.update(step=obs.step, semantic_result=sem_res, ml_result=ml_res, structural_result=struct_res)
            dec_res = dec.decide(ml=ml_res, semantic=sem_res, temporal=temp_res, structural=struct_res)

            is_alert = dec_res.classification in ("POTENTIAL_ATTACK", "COORDINATED_ATTACK")

            if label == 1:
                if is_alert:
                    tp += 1
                else:
                    fn += 1
            else:
                if is_alert:
                    fp += 1
                else:
                    tn += 1

            last_obs = obs
            history_list.append(obs)
            if len(history_list) > 20:
                history_list.pop(0)

        return tp, fp, tn, fn

    def approve_proposal(
        self,
        proposal_id: str,
        operator_name: str = "SecurityOperator",
    ) -> HardeningProposal:
        """Explicit operator approval gate for a validated proposal."""
        if proposal_id not in self.proposals:
            raise KeyError(f"Hardening proposal '{proposal_id}' not found.")

        proposal = self.proposals[proposal_id]

        if proposal.status == "REJECTED":
            raise ValueError(f"Cannot approve rejected proposal '{proposal_id}'.")
        if proposal.status not in ("PENDING_APPROVAL", "VALIDATED"):
            raise ValueError(
                f"Proposal '{proposal_id}' is in state '{proposal.status}'; "
                f"must be 'PENDING_APPROVAL' or 'VALIDATED' to approve."
            )

        proposal.operator_approved = True
        proposal.approved_by = operator_name
        proposal.approval_timestamp = datetime.now(timezone.utc).isoformat()
        proposal.status = "APPROVED"

        self._log_audit_event(
            event_type="HARDENING_PROPOSAL_APPROVED",
            severity="INFO",
            message=f"Operator '{operator_name}' approved hardening proposal {proposal_id}.",
            metadata={
                "proposal_id": proposal_id,
                "approved_by": operator_name,
                "target_parameter": proposal.target_parameter,
                "proposed_value": proposal.proposed_value,
            },
        )

        return proposal

    def activate_proposal(self, proposal_id: str) -> HardeningProposal:
        """Activate an approved hardening proposal, safely applying it to production engines."""
        if proposal_id not in self.proposals:
            raise KeyError(f"Hardening proposal '{proposal_id}' not found.")

        proposal = self.proposals[proposal_id]

        # Security control: explicit operator approval strictly required
        if not proposal.operator_approved or proposal.status != "APPROVED":
            raise PermissionError(
                f"Proposal '{proposal_id}' cannot be activated: explicit operator approval is required."
            )

        target_param = proposal.target_parameter
        new_val = proposal.proposed_value
        old_val = self.current_parameters.get(target_param, 0.50)

        # Apply to live production engines
        self.current_parameters[target_param] = new_val
        self._apply_parameter_to_service(target_param, new_val)

        proposal.status = "ACTIVE"
        proposal.activated_at = datetime.now(timezone.utc).isoformat()
        if proposal_id not in self.active_proposal_ids:
            self.active_proposal_ids.append(proposal_id)

        self._log_audit_event(
            event_type="HARDENING_PROPOSAL_ACTIVATED",
            severity="ALERT",
            message=(
                f"Activated hardening proposal {proposal_id}: "
                f"updated {target_param} from {old_val} to {new_val}."
            ),
            metadata={
                "proposal_id": proposal_id,
                "target_parameter": target_param,
                "old_value": old_val,
                "new_value": new_val,
            },
        )

        logger.info(f"Activated proposal {proposal_id}: {target_param}={new_val}")
        return proposal

    def _apply_parameter_to_service(self, parameter: str, value: float) -> None:
        """Update live component engine parameter in DefenderService."""
        if self.service is None:
            return

        if parameter == "c1_tolerance" and hasattr(self.service, "semantic_engine"):
            self.service.semantic_engine.c1_tolerance = value
        elif parameter == "c2_tolerance" and hasattr(self.service, "semantic_engine"):
            self.service.semantic_engine.c2_tolerance = value
        elif parameter == "primary_risk_threshold" and hasattr(self.service, "decision_engine"):
            self.service.decision_engine.primary_risk_threshold = value
        elif parameter == "suspicious_risk_threshold" and hasattr(self.service, "decision_engine"):
            self.service.decision_engine.suspicious_risk_threshold = value

    def rollback(self, proposal_id: Optional[str] = None) -> Dict[str, Any]:
        """Roll back an active proposal or all active hardening adjustments to baseline configuration."""
        if proposal_id is not None:
            if proposal_id not in self.proposals:
                raise KeyError(f"Proposal '{proposal_id}' not found.")
            proposal = self.proposals[proposal_id]
            param = proposal.target_parameter
            baseline_val = self.baseline_config.get(param, 0.50)

            # Revert parameter
            self.current_parameters[param] = baseline_val
            self._apply_parameter_to_service(param, baseline_val)

            proposal.status = "ROLLED_BACK"
            proposal.rolled_back_at = datetime.now(timezone.utc).isoformat()
            if proposal_id in self.active_proposal_ids:
                self.active_proposal_ids.remove(proposal_id)

            self._log_audit_event(
                event_type="HARDENING_ROLLED_BACK",
                severity="WARNING",
                message=f"Rolled back hardening proposal {proposal_id}: restored {param} to {baseline_val}.",
                metadata={
                    "proposal_id": proposal_id,
                    "target_parameter": param,
                    "restored_value": baseline_val,
                },
            )
            return {"rolled_back_proposal": proposal_id, "restored_parameters": {param: baseline_val}}

        # Roll back all parameters to baseline
        restored = {}
        for param, baseline_val in self.baseline_config.items():
            self.current_parameters[param] = baseline_val
            self._apply_parameter_to_service(param, baseline_val)
            restored[param] = baseline_val

        for pid in list(self.active_proposal_ids):
            if pid in self.proposals:
                self.proposals[pid].status = "ROLLED_BACK"
                self.proposals[pid].rolled_back_at = datetime.now(timezone.utc).isoformat()
        self.active_proposal_ids.clear()

        self._log_audit_event(
            event_type="HARDENING_ROLLED_BACK",
            severity="WARNING",
            message="Rolled back all hardening adjustments to baseline configuration.",
            metadata={"restored_parameters": restored},
        )
        return {"restored_parameters": restored}

    def reset(self) -> None:
        """Reset hardening engine state, restoring baseline parameters and clearing proposals."""
        for param, baseline_val in self.baseline_config.items():
            self.current_parameters[param] = baseline_val
            self._apply_parameter_to_service(param, baseline_val)
        self.missed_attacks.clear()
        self.proposals.clear()
        self.active_proposal_ids.clear()
        logger.info("Reset HardeningEngine state to initial baseline.")

    def get_status(self) -> HardeningStatus:
        """Return high-level hardening status."""
        active_cnt = len(self.active_proposal_ids)
        pending_cnt = sum(1 for p in self.proposals.values() if p.status in ("PENDING_VALIDATION", "VALIDATED", "PENDING_APPROVAL", "APPROVED"))
        rejected_cnt = sum(1 for p in self.proposals.values() if p.status == "REJECTED")

        return HardeningStatus(
            active_proposals_count=active_cnt,
            pending_proposals_count=pending_cnt,
            rejected_proposals_count=rejected_cnt,
            missed_attacks_recorded=len(self.missed_attacks),
            active_parameters=dict(self.current_parameters),
            baseline_parameters=dict(self.baseline_config),
            is_hardened=active_cnt > 0,
        )

    def get_proposals(self) -> List[HardeningProposal]:
        """Return all proposals."""
        return list(self.proposals.values())

    def get_misses(self) -> List[MissedAttackReport]:
        """Return all missed attack reports."""
        return list(self.missed_attacks)
