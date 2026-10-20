"""Deterministic test suite for the Miss-Driven Self-Hardening Purple-Team Loop.

Verifies:
1. Capturing confirmed missed attacks and diagnosing root cause.
2. Generating bounded proposals for tolerance and threshold adjustments.
3. Validating proposals on independent validation splits.
4. Correctly passing valid improvements that maintain zero false positives.
5. Rejecting proposals that cause false-positive regressions.
6. Rejecting proposals that fail to improve detection objective.
7. Requiring explicit operator approval before activating any proposal (security boundary).
8. Rollback restoring baseline configuration exactly.
9. Zero regression on continuous normal operations.
10. Full SHA-256 cryptographic audit chain linkage across all hardening lifecycle events.
11. Clean reset behavior restoring baseline detector state and genesis hash.
12. Security API endpoint access control and validation.
"""

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.api.state import app_state
from app.config import settings
from app.defender.audit import GENESIS_HASH
from app.defender.hardening import (
    HardeningEngine,
    HardeningProposal,
    MissedAttackReport,
)
from app.defender.models import (
    MLResult,
    SecurityDecision,
    SemanticResult,
    StructuralResult,
    TemporalResult,
)
from app.defender.service import DefenderService
from app.evaluation.dataset import EvaluationRecord
from app.simulator.models import WarehouseObservation
from app.simulator.warehouse import ColdStorageWarehouse


def create_mock_record(
    step: int,
    inventory: float,
    free_capacity: float,
    capacity: float = 50.0,
    temperature: float = 4.2,
    humidity: float = 71.0,
    is_attack: bool = False,
    attack_type: str = "normal",
) -> EvaluationRecord:
    """Helper to create an EvaluationRecord for validation tests."""
    obs = WarehouseObservation(
        step=step,
        timestamp=f"2026-10-20T10:{step:02d}:00Z",
        warehouse="W01",
        temperature=temperature,
        humidity=humidity,
        inventory=round(inventory, 2),
        free_capacity=round(free_capacity, 2),
        capacity=round(capacity, 2),
        occupancy=round((inventory / capacity) * 100.0, 1),
        inbound=1.0,
        outbound=1.0,
        is_attack_injected=is_attack,
        attack_type=attack_type if is_attack else None,
    )
    return EvaluationRecord(
        record_id=f"REC-{step:04d}",
        observation=obs,
        ground_truth_label=1 if is_attack else 0,
        attack_type=attack_type if is_attack else "normal",
        episode_id="EP-TEST",
        step_in_episode=step,
    )


class TestMissDrivenHardeningLoop:
    """Test suite for the Miss-Driven Self-Hardening Purple-Team component."""

    def test_record_missed_attack_and_diagnose_cause(self):
        """Verify recording an undetected attack captures evidence and diagnoses cause."""
        service = DefenderService()
        engine = service.hardening_engine

        # Subtle coordinated weak attack: inventory=40.5, free_capacity=9.0, capacity=50.0
        # Discrepancy is 0.50t, which is <= c1_tolerance (0.50t)
        obs = WarehouseObservation(
            step=10,
            timestamp="2026-10-20T12:00:00Z",
            warehouse="W01",
            temperature=4.2,
            humidity=71.0,
            inventory=40.5,
            free_capacity=9.0,
            capacity=50.0,
            occupancy=81.0,
            inbound=1.0,
            outbound=1.0,
        )

        analysis = service.analyze(obs)
        assert analysis.decision.classification == "NORMAL"

        miss_report = engine.record_miss(
            observation=obs,
            analysis=analysis,
            attack_type="coordinated_weak",
            target="sensors_and_inventory",
            value=-1.5,
            step=10,
        )

        assert isinstance(miss_report, MissedAttackReport)
        assert miss_report.attack_type == "coordinated_weak"
        assert miss_report.diagnosed_cause == "STEALTHY_CAPACITY_SLACK_BELOW_C1_TOLERANCE"
        assert miss_report.detector_evidence["c1_diff"] == 0.50
        assert len(engine.get_misses()) == 1

        # Check audit event
        events = [e for e in service.events if e.event_type == "HARDENING_MISS_RECORDED"]
        assert len(events) == 1
        assert "coordinated_weak" in events[0].message
        assert events[0].event_hash != ""

    def test_proposal_generation_and_parameter_bounds(self):
        """Verify proposed adjustment is bounded and calculated properly."""
        service = DefenderService()
        engine = service.hardening_engine

        obs = WarehouseObservation(
            step=5,
            timestamp="2026-10-20T12:00:00Z",
            warehouse="W01",
            temperature=4.2,
            humidity=71.0,
            inventory=40.5,
            free_capacity=9.0,
            capacity=50.0,
            occupancy=81.0,
            inbound=1.0,
            outbound=1.0,
        )
        analysis = service.analyze(obs)
        miss = engine.record_miss(observation=obs, analysis=analysis, attack_type="coordinated_weak")

        proposal = engine.generate_proposal(miss)
        assert proposal is not None
        assert proposal.target_parameter == "c1_tolerance"
        assert proposal.current_value == 0.50
        assert proposal.proposed_value == 0.40  # 0.50 * 0.8
        assert proposal.parameter_bounds == (0.10, 0.50)
        assert 0.10 <= proposal.proposed_value <= 0.50
        assert proposal.status == "PENDING_VALIDATION"
        assert proposal.operator_approved is False

    def test_valid_improvement_proposal_passes_validation(self):
        """Verify candidate proposal improving recall with 0% FPR passes validation."""
        service = DefenderService()
        engine = service.hardening_engine

        # Create validation set: 20 normal samples (diff=0.0) + 20 attack samples (diff=0.50)
        val_records = []
        for i in range(20):
            # Normal: inventory + free_capacity = 42.0 + 8.0 = 50.0 (diff = 0.0)
            val_records.append(
                create_mock_record(step=i, inventory=42.0, free_capacity=8.0, is_attack=False)
            )
        for i in range(20, 40):
            # Attack: inventory + free_capacity = 40.5 + 9.0 = 49.5 (diff = 0.50)
            val_records.append(
                create_mock_record(
                    step=i,
                    inventory=40.5,
                    free_capacity=9.0,
                    is_attack=True,
                    attack_type="coordinated_weak",
                )
            )

        # Baseline: c1_tolerance = 0.50 -> attack diff 0.50 <= 0.50 (undetected, recall = 0%)
        # Candidate: c1_tolerance = 0.40 -> attack diff 0.50 > 0.40 (detected, recall = 100%)
        # Normal samples diff 0.00 <= 0.40 -> 0 false positives (FPR = 0%)
        proposal = HardeningProposal(
            trigger_miss_id="MISS-001",
            adjustment_type="TOLERANCE_TIGHTENING",
            target_parameter="c1_tolerance",
            current_value=0.50,
            proposed_value=0.40,
            parameter_bounds=(0.10, 0.50),
            rationale="Tighten tolerance to catch 0.50 discrepancy",
        )
        engine.proposals[proposal.proposal_id] = proposal

        val_result = engine.validate_proposal(
            proposal=proposal,
            validation_records=val_records,
            max_allowed_fpr=0.001,
        )

        assert val_result.verdict == "PASSED"
        assert val_result.passed_fpr_limit is True
        assert val_result.improved_objective is True
        assert val_result.candidate_recall > val_result.baseline_recall
        assert val_result.candidate_recall == 1.0
        assert val_result.recall_delta >= 0.90
        assert val_result.candidate_fpr == 0.0
        assert proposal.status == "PENDING_APPROVAL"

        # Check audit event
        events = [e for e in service.events if e.event_type == "HARDENING_PROPOSAL_VALIDATED"]
        assert len(events) == 1

    def test_false_positive_regression_rejected(self):
        """Verify proposal causing false positives on normal data is strictly rejected."""
        service = DefenderService()
        engine = service.hardening_engine

        # Normal samples have slight variance: diff = 0.05
        val_records = []
        for i in range(20):
            val_records.append(
                create_mock_record(step=i, inventory=42.05, free_capacity=8.0, is_attack=False)
            )
        for i in range(20, 40):
            val_records.append(
                create_mock_record(
                    step=i, inventory=40.5, free_capacity=9.0, is_attack=True, attack_type="coordinated_weak"
                )
            )

        # Proposed tolerance 0.02 is smaller than normal variance 0.05 -> causes FPR > 0!
        proposal = HardeningProposal(
            trigger_miss_id="MISS-FP",
            adjustment_type="TOLERANCE_TIGHTENING",
            target_parameter="c1_tolerance",
            current_value=0.50,
            proposed_value=0.02,
            parameter_bounds=(0.01, 0.50),
            rationale="Overly aggressive tolerance that flags normal telemetry",
        )
        engine.proposals[proposal.proposal_id] = proposal

        val_result = engine.validate_proposal(
            proposal=proposal,
            validation_records=val_records,
            max_allowed_fpr=0.001,
        )

        assert val_result.verdict == "REJECTED"
        assert val_result.passed_fpr_limit is False
        assert val_result.candidate_fpr > 0.0
        assert "False-positive regression" in str(val_result.rejection_reason)
        assert proposal.status == "REJECTED"

        # Check audit event
        events = [e for e in service.events if e.event_type == "HARDENING_PROPOSAL_REJECTED"]
        assert len(events) == 1

    def test_no_improvement_proposal_rejected(self):
        """Verify proposal failing to improve recall or F1 is rejected."""
        service = DefenderService()
        engine = service.hardening_engine

        val_records = [
            create_mock_record(step=0, inventory=42.0, free_capacity=8.0, is_attack=False),
            create_mock_record(step=1, inventory=40.5, free_capacity=9.0, is_attack=True),
        ]

        # Loosening tolerance to 0.50 -> fails to improve recall
        proposal = HardeningProposal(
            trigger_miss_id="MISS-SAME",
            adjustment_type="TOLERANCE_TIGHTENING",
            target_parameter="c1_tolerance",
            current_value=0.50,
            proposed_value=0.50,
            parameter_bounds=(0.10, 0.50),
            rationale="No-op parameter change",
        )
        engine.proposals[proposal.proposal_id] = proposal

        val_result = engine.validate_proposal(proposal=proposal, validation_records=val_records)
        assert val_result.verdict == "REJECTED"
        assert val_result.improved_objective is False
        assert "Failed to improve objective" in str(val_result.rejection_reason)
        assert proposal.status == "REJECTED"

    def test_operator_approval_workflow_and_security_boundary(self):
        """Verify operator approval is strictly required before activation (no automated attacker bypass)."""
        service = DefenderService()
        engine = service.hardening_engine

        proposal = HardeningProposal(
            trigger_miss_id="MISS-AUTH",
            adjustment_type="TOLERANCE_TIGHTENING",
            target_parameter="c1_tolerance",
            current_value=0.50,
            proposed_value=0.40,
            parameter_bounds=(0.10, 0.50),
            rationale="Test approval gate",
            status="PENDING_APPROVAL",
        )
        engine.proposals[proposal.proposal_id] = proposal

        # 1. Direct activation without operator approval MUST fail
        with pytest.raises(PermissionError) as exc_info:
            engine.activate_proposal(proposal.proposal_id)
        assert "explicit operator approval is required" in str(exc_info.value)
        assert service.semantic_engine.c1_tolerance == 0.50  # Unmodified

        # 2. Cannot approve rejected proposals
        rejected_prop = HardeningProposal(
            trigger_miss_id="MISS-REJ",
            adjustment_type="TOLERANCE_TIGHTENING",
            target_parameter="c1_tolerance",
            current_value=0.50,
            proposed_value=0.01,
            parameter_bounds=(0.01, 0.50),
            rationale="Rejected",
            status="REJECTED",
        )
        engine.proposals[rejected_prop.proposal_id] = rejected_prop
        with pytest.raises(ValueError):
            engine.approve_proposal(rejected_prop.proposal_id)

        # 3. Valid operator approval
        approved = engine.approve_proposal(proposal.proposal_id, operator_name="SecOps-Lead")
        assert approved.operator_approved is True
        assert approved.approved_by == "SecOps-Lead"
        assert approved.status == "APPROVED"

        # 4. Activation succeeds after operator approval
        activated = engine.activate_proposal(proposal.proposal_id)
        assert activated.status == "ACTIVE"
        assert service.semantic_engine.c1_tolerance == 0.40
        assert engine.current_parameters["c1_tolerance"] == 0.40

        # Check audit events
        approved_events = [e for e in service.events if e.event_type == "HARDENING_PROPOSAL_APPROVED"]
        activated_events = [e for e in service.events if e.event_type == "HARDENING_PROPOSAL_ACTIVATED"]
        assert len(approved_events) == 1
        assert len(activated_events) == 1
        assert "SecOps-Lead" in approved_events[0].message

    def test_rollback_restores_baseline_configuration(self):
        """Verify rollback restores baseline production parameters."""
        service = DefenderService()
        engine = service.hardening_engine

        assert service.semantic_engine.c1_tolerance == 0.50

        # Create, approve, and activate proposal
        proposal = HardeningProposal(
            trigger_miss_id="MISS-RB",
            adjustment_type="TOLERANCE_TIGHTENING",
            target_parameter="c1_tolerance",
            current_value=0.50,
            proposed_value=0.35,
            parameter_bounds=(0.10, 0.50),
            rationale="Rollback test",
            status="PENDING_APPROVAL",
        )
        engine.proposals[proposal.proposal_id] = proposal
        engine.approve_proposal(proposal.proposal_id)
        engine.activate_proposal(proposal.proposal_id)

        assert service.semantic_engine.c1_tolerance == 0.35
        assert engine.current_parameters["c1_tolerance"] == 0.35

        # Trigger rollback
        result = engine.rollback(proposal.proposal_id)
        assert result["rolled_back_proposal"] == proposal.proposal_id
        assert service.semantic_engine.c1_tolerance == 0.50
        assert engine.current_parameters["c1_tolerance"] == 0.50
        assert proposal.status == "ROLLED_BACK"

        # Check rollback audit event
        rb_events = [e for e in service.events if e.event_type == "HARDENING_ROLLED_BACK"]
        assert len(rb_events) == 1
        assert "restored c1_tolerance to 0.5" in rb_events[0].message

    def test_normal_operation_regression(self):
        """Verify that applying a valid hardening adjustment causes 0 false positives on continuous normal data."""
        service = DefenderService()
        warehouse = ColdStorageWarehouse(seed=42)

        # Baseline evaluation on 50 normal steps
        baseline_alerts = 0
        normal_obs_list = []
        for _ in range(50):
            obs = warehouse.step()
            normal_obs_list.append(obs)
            res = service.analyze(obs)
            if res.decision.classification in ("POTENTIAL_ATTACK", "COORDINATED_ATTACK"):
                baseline_alerts += 1

        assert baseline_alerts == 0

        # Apply hardened C1 tolerance (0.40)
        proposal = HardeningProposal(
            trigger_miss_id="MISS-NORM",
            adjustment_type="TOLERANCE_TIGHTENING",
            target_parameter="c1_tolerance",
            current_value=0.50,
            proposed_value=0.40,
            parameter_bounds=(0.10, 0.50),
            rationale="Test normal regression",
            status="PENDING_APPROVAL",
        )
        service.hardening_engine.proposals[proposal.proposal_id] = proposal
        service.hardening_engine.approve_proposal(proposal.proposal_id)
        service.hardening_engine.activate_proposal(proposal.proposal_id)

        # Re-evaluate all 50 normal observations with fresh service state
        hardened_service = DefenderService()
        hardened_service.semantic_engine.c1_tolerance = 0.40
        hardened_alerts = 0
        for obs in normal_obs_list:
            res = hardened_service.analyze(obs)
            if res.decision.classification in ("POTENTIAL_ATTACK", "COORDINATED_ATTACK"):
                hardened_alerts += 1

        assert hardened_alerts == 0, "Hardened system produced false positives on normal telemetry!"

    def test_sha256_audit_chain_links_all_hardening_events(self):
        """Verify that all hardening events maintain SHA-256 hash chaining and tamper detection."""
        service = DefenderService()
        engine = service.hardening_engine

        obs = WarehouseObservation(
            step=1,
            timestamp="2026-10-20T12:00:00Z",
            warehouse="W01",
            temperature=4.2,
            humidity=71.0,
            inventory=40.5,
            free_capacity=9.0,
            capacity=50.0,
            occupancy=81.0,
            inbound=1.0,
            outbound=1.0,
        )
        analysis = service.analyze(obs)

        # Full lifecycle: miss -> proposal -> approval -> activation -> rollback
        miss = engine.record_miss(observation=obs, analysis=analysis, attack_type="coordinated_weak")
        prop = engine.generate_proposal(miss)
        prop.status = "PENDING_APPROVAL"
        engine.approve_proposal(prop.proposal_id)
        engine.activate_proposal(prop.proposal_id)
        engine.rollback(prop.proposal_id)

        # Verify audit chain integrity
        verif = service.verify_audit_chain()
        assert verif.valid is True
        assert verif.error is None
        assert verif.total_events >= 5

        # Tampering with any hardening event payload MUST invalidate the chain
        service.events[-1].message = "Tampered unauthorized audit log"
        tampered_verif = service.verify_audit_chain()
        assert tampered_verif.valid is False
        assert tampered_verif.failed_event_index is not None

    def test_reset_behavior_restores_baseline_configuration(self):
        """Verify service.reset() cleanly reverts all hardening parameters to baseline."""
        service = DefenderService()
        engine = service.hardening_engine

        # Modify parameters via active proposal
        proposal = HardeningProposal(
            trigger_miss_id="MISS-RST",
            adjustment_type="TOLERANCE_TIGHTENING",
            target_parameter="c1_tolerance",
            current_value=0.50,
            proposed_value=0.35,
            parameter_bounds=(0.10, 0.50),
            rationale="Reset test",
            status="PENDING_APPROVAL",
        )
        engine.proposals[proposal.proposal_id] = proposal
        engine.approve_proposal(proposal.proposal_id)
        engine.activate_proposal(proposal.proposal_id)

        assert service.semantic_engine.c1_tolerance == 0.35

        # Execute service reset
        service.reset()

        assert service.semantic_engine.c1_tolerance == 0.50
        assert engine.current_parameters["c1_tolerance"] == 0.50
        assert len(engine.active_proposal_ids) == 0
        assert service.latest_event_hash == GENESIS_HASH

    def test_api_security_endpoints_for_hardening(self):
        """Verify the REST API endpoints for proposal listing, operator approval, and rollback."""
        client = TestClient(app)

        # 1. Query proposals via API
        resp = client.get("/api/security/hardening/proposals")
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert "proposals" in data

        # 2. Add proposal to app_state for testing API approval
        proposal = HardeningProposal(
            trigger_miss_id="MISS-API",
            adjustment_type="TOLERANCE_TIGHTENING",
            target_parameter="c1_tolerance",
            current_value=0.50,
            proposed_value=0.40,
            parameter_bounds=(0.10, 0.50),
            rationale="API test",
            status="PENDING_APPROVAL",
        )
        app_state.defender.hardening_engine.proposals[proposal.proposal_id] = proposal

        # 3. Approve via API without approval confirmation -> 400
        resp_unapproved = client.post(
            f"/api/security/hardening/proposals/{proposal.proposal_id}/approve",
            json={"approved": False, "operator_name": "TestOp"},
        )
        assert resp_unapproved.status_code == 400

        # 4. Operator approves via API -> 200 OK
        resp_approved = client.post(
            f"/api/security/hardening/proposals/{proposal.proposal_id}/approve",
            json={"approved": True, "operator_name": "SecOpsOfficer"},
        )
        assert resp_approved.status_code == 200
        body = resp_approved.json()
        assert body["success"] is True
        assert body["proposal"]["status"] == "ACTIVE"
        assert app_state.defender.semantic_engine.c1_tolerance == 0.40

        # 5. Rollback via API
        resp_rb = client.post(
            f"/api/security/hardening/rollback?proposal_id={proposal.proposal_id}"
        )
        assert resp_rb.status_code == 200
        assert app_state.defender.semantic_engine.c1_tolerance == 0.50
