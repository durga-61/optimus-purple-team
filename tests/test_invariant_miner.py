"""Tests for dynamic semantic invariant discovery, validation, and rollback."""

import pytest

from app.defender.invariant_miner import (
    ActiveInvariant,
    InvariantCandidate,
    InvariantMiner,
)
from app.defender.semantic import SemanticEngine
from app.evaluation.dataset import (
    EvaluationRecord,
    generate_attack_dataset,
    generate_normal_dataset,
)
from app.simulator.models import WarehouseObservation


def make_record(
    step: int,
    temperature: float = 4.2,
    humidity: float = 71.0,
    inventory: float = 42.0,
    free_capacity: float = 8.0,
    is_attack: bool = False,
) -> EvaluationRecord:
    observation = WarehouseObservation(
        step=step,
        timestamp=f"2026-10-20T10:{step % 60:02d}:00Z",
        warehouse="W01",
        temperature=temperature,
        humidity=humidity,
        inventory=inventory,
        free_capacity=free_capacity,
        capacity=50.0,
        occupancy=round(inventory / 50.0 * 100.0, 1),
        inbound=1.0,
        outbound=1.0,
        is_attack_injected=is_attack,
    )
    return EvaluationRecord(
        record_id=f"INV-{step:04d}",
        observation=observation,
        ground_truth_label=1 if is_attack else 0,
        attack_type="sensor_spoofing" if is_attack else "normal",
        episode_id="EP-INV",
        step_in_episode=step,
    )


class TestInvariantDiscovery:
    def test_discovers_explicit_candidate_families(self):
        records = generate_normal_dataset(num_samples=30, seed=42)
        miner = InvariantMiner()
        candidates = miner.discover(records)

        assert len(candidates) == 9
        ids = {candidate.candidate_id for candidate in candidates}
        assert "INV-CAPACITY-RESIDUAL" in ids
        assert "INV-FLOW-RESIDUAL" in ids
        assert "INV-TEMP-ENVELOPE" in ids
        assert "INV-TEMP-SLEW" in ids
        assert "INV-SHIPMENT-RATE" in ids
        assert all(candidate.status == "CANDIDATE" for candidate in candidates)
        assert all(candidate.discovery_coverage == 1.0 for candidate in candidates)
        assert all(candidate.kind in {"residual", "envelope", "slew", "rate"} for candidate in candidates)
        assert all(candidate.tolerance >= 0.0 for candidate in candidates)

    def test_discovery_requires_enough_clean_history(self):
        with pytest.raises(ValueError):
            InvariantMiner().discover(generate_normal_dataset(num_samples=9, seed=42))

    def test_discovery_rejects_labeled_attacks(self):
        attacks = generate_attack_dataset(num_samples_per_class=2, seed=42, episode_length=5)
        with pytest.raises(ValueError):
            InvariantMiner().discover(attacks)


class TestInvariantValidation:
    def _normal_and_attack(self):
        normals = [make_record(i, temperature=4.2) for i in range(20)]
        attacks = [make_record(100 + i, temperature=30.0, is_attack=True) for i in range(10)]
        return normals, attacks

    def test_accepts_discriminating_stable_candidate(self):
        normals, attacks = self._normal_and_attack()
        miner = InvariantMiner()
        candidate = InvariantCandidate(
            candidate_id="INV-TEMP-ACCEPT",
            name="Temperature envelope",
            family="temperature",
            kind="envelope",
            field="temperature",
            parameters={"min": 0.0, "max": 8.0},
        )
        miner.candidates[candidate.candidate_id] = candidate

        miner.validate([candidate], normal_records=normals, attack_records=attacks)

        assert candidate.status == "VALIDATED"
        assert candidate.validation_coverage == 1.0
        assert candidate.false_positive_rate == 0.0
        assert candidate.attack_detection_rate == 1.0
        assert candidate.per_class_detection == {"sensor_spoofing": 1.0}
        assert candidate.validated_at is not None

    def test_rejects_overly_restrictive_candidate(self):
        normals, attacks = self._normal_and_attack()
        miner = InvariantMiner()
        candidate = InvariantCandidate(
            candidate_id="INV-TEMP-TIGHT",
            name="Overly tight temperature envelope",
            family="temperature",
            kind="envelope",
            field="temperature",
            parameters={"min": 100.0, "max": 200.0},
        )
        miner.candidates[candidate.candidate_id] = candidate

        miner.validate([candidate], normal_records=normals, attack_records=attacks)

        assert candidate.status == "REJECTED"
        assert candidate.false_positive_rate == 1.0
        assert "Unstable or overly restrictive" in candidate.rejection_reason

    def test_rejects_candidate_without_attack_discrimination(self):
        normals, attacks = self._normal_and_attack()
        miner = InvariantMiner()
        candidate = InvariantCandidate(
            candidate_id="INV-TEMP-WIDE",
            name="Wide temperature envelope",
            family="temperature",
            kind="envelope",
            field="temperature",
            parameters={"min": -100.0, "max": 100.0},
        )
        miner.candidates[candidate.candidate_id] = candidate

        miner.validate([candidate], normal_records=normals, attack_records=attacks)

        assert candidate.status == "REJECTED"
        assert candidate.attack_detection_rate == 0.0
        assert "Does not discriminate" in candidate.rejection_reason

    def test_rejects_candidate_redundant_with_existing_constraint(self):
        normals = [make_record(i) for i in range(20)]
        attacks = [
            make_record(100 + i, inventory=35.0, free_capacity=9.0, is_attack=True)
            for i in range(10)
        ]
        miner = InvariantMiner()
        candidate = InvariantCandidate(
            candidate_id="INV-CAPACITY-DUPLICATE",
            name="Capacity residual duplicate",
            family="capacity",
            kind="residual",
            tolerance=0.0,
            duplicate_of="C1",
        )
        miner.candidates[candidate.candidate_id] = candidate

        miner.validate([candidate], normal_records=normals, attack_records=attacks)

        assert candidate.status == "REJECTED"
        assert "Redundant with existing C1 constraint" in candidate.rejection_reason

    def test_validation_requires_independent_data(self):
        miner = InvariantMiner()
        with pytest.raises(ValueError):
            miner.validate()
        with pytest.raises(ValueError):
            miner.validate(normal_records=[], attack_records=[make_record(1)])


class TestInvariantActivationAndRollback:
    def _validated_miner(self):
        normals = [make_record(i) for i in range(10)]
        attacks = [make_record(100 + i, temperature=30.0, is_attack=True) for i in range(5)]
        miner = InvariantMiner()
        candidate = InvariantCandidate(
            candidate_id="INV-TEMP-ACTIVE",
            name="Temperature envelope",
            family="temperature",
            kind="envelope",
            field="temperature",
            parameters={"min": 0.0, "max": 8.0},
        )
        miner.candidates[candidate.candidate_id] = candidate
        miner.validate([candidate], normal_records=normals, attack_records=attacks)
        assert candidate.status == "VALIDATED"
        return miner

    def test_activation_requires_explicit_operator_approval(self):
        miner = self._validated_miner()
        engine = SemanticEngine()

        with pytest.raises(PermissionError):
            miner.activate(semantic_engine=engine)
        assert engine.custom_invariants == []
        assert miner.get_candidates("VALIDATED")

    def test_activation_installs_invariant_and_rollback_removes_it(self):
        miner = self._validated_miner()
        engine = SemanticEngine()

        active = miner.activate(semantic_engine=engine, operator_approved=True)

        assert len(active) == 1
        assert engine.custom_invariants == active
        assert miner.get_candidates("ACTIVE")[0].candidate_id == "INV-TEMP-ACTIVE"

        rolled_back = miner.rollback(semantic_engine=engine)

        assert rolled_back == ["INV-TEMP-ACTIVE"]
        assert engine.custom_invariants == []
        assert miner.get_candidates("ROLLED_BACK")[0].candidate_id == "INV-TEMP-ACTIVE"


class TestSemanticIntegration:
    def test_custom_violation_contributes_capped_hard_evidence(self):
        engine = SemanticEngine()
        invariant = ActiveInvariant(
            candidate_id="INV-TEMP-ACTIVE",
            name="Temperature envelope",
            family="temperature",
            kind="envelope",
            tolerance=0.0,
            field="temperature",
            parameters={"min": 0.0, "max": 8.0},
        )
        engine.add_invariant(invariant)

        observation = WarehouseObservation(
            step=1,
            timestamp="2026-10-20T10:00:00Z",
            warehouse="W01",
            temperature=30.0,
            humidity=71.0,
            inventory=42.0,
            free_capacity=8.0,
            capacity=50.0,
            occupancy=84.0,
            inbound=1.0,
            outbound=1.0,
        )
        result = engine.analyze(observation)

        assert "INV-TEMP-ACTIVE" in result.violated_constraints
        assert result.evidence["active_invariant_count"] == 1
        assert result.evidence["custom_invariant_violations"] == {"INV-TEMP-ACTIVE": 22.0}
        assert result.semantic_score >= 0.30

        engine.clear_invariants()
        baseline = engine.analyze(observation)
        assert "INV-TEMP-ACTIVE" not in baseline.violated_constraints
        assert baseline.evidence["active_invariant_count"] == 0

    def test_duplicate_and_invalid_invariants_are_rejected(self):
        engine = SemanticEngine()
        invariant = ActiveInvariant(
            candidate_id="INV-TEMP-ACTIVE",
            name="Temperature envelope",
            family="temperature",
            kind="envelope",
            tolerance=0.0,
            field="temperature",
            parameters={"min": 0.0, "max": 8.0},
        )
        engine.add_invariant(invariant)

        with pytest.raises(ValueError):
            engine.add_invariant(invariant)
        with pytest.raises(TypeError):
            engine.add_invariant(object())
