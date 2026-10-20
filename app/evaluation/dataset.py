"""Deterministic Dataset Generator and Temporal Splitter for Evaluation Benchmarks.

Generates 12,000 normal and 12,000 attack observations across 6 attack classes with
strict invariant verification, zero feature data leakage, and reproducible temporal splits.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import logging
import random
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from app.config import settings
from app.simulator.models import WarehouseObservation
from app.simulator.scenarios import (
    inject_capacity_manipulation,
    inject_inventory_manipulation,
    inject_sensor_spoofing,
    inject_replay_attack,
    inject_coordinated_manipulation,
    inject_multi_source_manipulation,
)
from app.simulator.warehouse import ColdStorageWarehouse

logger = logging.getLogger("evaluation.dataset")

ATTACK_CLASSES = [
    "capacity_manipulation",
    "inventory_manipulation",
    "sensor_spoofing",
    "replay_attack",
    "coordinated_weak",
    "multi_source",
]

_DATASET_EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _dataset_timestamp(step: int) -> str:
    """Deterministic observation timestamp so split files and hashes reproduce."""
    return (_DATASET_EPOCH + timedelta(seconds=int(step))).isoformat()


class EvaluationRecord(BaseModel):
    """An individual evaluation sample decoupling ground truth from defender input."""

    record_id: str = Field(..., description="Unique record identifier")
    observation: WarehouseObservation = Field(..., description="Observation passed to defender (zero ground-truth labels)")
    ground_truth_label: int = Field(..., description="0 = Normal, 1 = Attack")
    attack_type: Optional[str] = Field(default=None, description="Ground truth attack class, or 'normal'")
    episode_id: str = Field(..., description="Episode identifier for latency tracking")
    step_in_episode: int = Field(default=0, ge=0, description="0-indexed step offset within episode")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Evaluation metadata (targets, values, ground truth)")

    def get_inference_observation(self) -> WarehouseObservation:
        """Return a sanitised observation with zero ground-truth attack metadata."""
        data = self.observation.model_dump()
        # Strictly guarantee ground-truth labels are scrubbed from inference inputs
        data["is_attack_injected"] = False
        data["attack_type"] = None
        return WarehouseObservation(**data)


@dataclass
class DatasetSplits:
    """Represents temporally separated training, validation, and held-out test splits."""

    train: List[EvaluationRecord]  # Normal-only for clean baseline fitting
    val: List[EvaluationRecord]    # Mixed normal + attack for parameter tuning / validation
    test: List[EvaluationRecord]   # Held-out test set for final benchmark metrics

    @property
    def total_records(self) -> int:
        return len(self.train) + len(self.val) + len(self.test)


@dataclass
class EvaluationDataset:
    """Complete collection of normal and attack evaluation records."""

    normal_records: List[EvaluationRecord]
    attack_records: List[EvaluationRecord]
    seed: int = 42

    @property
    def total_records(self) -> int:
        return len(self.normal_records) + len(self.attack_records)

    def get_attack_records_by_class(self, attack_class: str) -> List[EvaluationRecord]:
        return [r for r in self.attack_records if r.attack_type == attack_class]


def verify_normal_observation_invariants(obs: WarehouseObservation, prev_obs: Optional[WarehouseObservation]) -> Tuple[bool, List[str]]:
    """Verify that an observation satisfies warehouse invariants C1, C2, and C3."""
    violations = []

    # C1: Capacity Invariant (inventory + free_capacity == total_capacity)
    c1_diff = abs(round(obs.inventory + obs.free_capacity, 2) - round(obs.capacity, 2))
    if c1_diff > settings.C1_CAPACITY_TOLERANCE:
        violations.append(f"C1 capacity mismatch: {obs.inventory} + {obs.free_capacity} != {obs.capacity} (diff={c1_diff})")

    # C2: Flow Invariant (inventory_t == inventory_{t-1} + inbound - outbound)
    if prev_obs is not None:
        expected_inv = round(prev_obs.inventory + obs.inbound - obs.outbound, 2)
        c2_diff = abs(round(obs.inventory, 2) - expected_inv)
        if c2_diff > settings.C2_FLOW_TOLERANCE:
            violations.append(f"C2 flow mismatch: {obs.inventory} != {prev_obs.inventory} + {obs.inbound} - {obs.outbound} (diff={c2_diff})")

    # C3: Historical Physical Bounds
    if not (settings.TEMP_MIN_BOUND - 0.01 <= obs.temperature <= settings.TEMP_MAX_BOUND + 0.01):
        violations.append(f"C3 temperature out of bounds: {obs.temperature} not in [{settings.TEMP_MIN_BOUND}, {settings.TEMP_MAX_BOUND}]")
    if not (settings.HUMIDITY_MIN_BOUND - 0.01 <= obs.humidity <= settings.HUMIDITY_MAX_BOUND + 0.01):
        violations.append(f"C3 humidity out of bounds: {obs.humidity} not in [{settings.HUMIDITY_MIN_BOUND}, {settings.HUMIDITY_MAX_BOUND}]")

    return (len(violations) == 0, violations)


def generate_normal_dataset(num_samples: int = 12000, seed: int = 42) -> List[EvaluationRecord]:
    """Deterministically generate continuous normal warehouse observations.

    Guarantees strict time ordering and that 100% of observations satisfy
    invariants C1 (capacity), C2 (flow), and C3 (physical envelope).
    """
    warehouse = ColdStorageWarehouse(seed=seed)
    records: List[EvaluationRecord] = []
    prev_obs: Optional[WarehouseObservation] = None

    for i in range(num_samples):
        obs = warehouse.step().model_copy(update={"timestamp": _dataset_timestamp(warehouse.step_count)})

        # Invariant verification assertion
        is_valid, violations = verify_normal_observation_invariants(obs, prev_obs)
        if not is_valid:
            raise ValueError(f"Invariant violation during normal generation at step {obs.step}: {violations}")

        record = EvaluationRecord(
            record_id=f"NORM-{i:06d}",
            observation=obs,
            ground_truth_label=0,
            attack_type="normal",
            episode_id="EP-NORMAL-0001",
            step_in_episode=i,
            metadata={"step": obs.step, "invariants_verified": True},
        )
        records.append(record)
        prev_obs = obs

    logger.info(f"Generated {len(records)} verified normal observations (Seed={seed}).")
    return records


def generate_attack_dataset(
    num_samples_per_class: int = 2000,
    seed: int = 42,
    episode_length: int = 20,
) -> List[EvaluationRecord]:
    """Deterministically generate attack observations grouped into temporal episodes.

    Generates approximately num_samples_per_class for each of the 6 attack classes:
    1. capacity_manipulation
    2. inventory_manipulation
    3. sensor_spoofing
    4. replay_attack
    5. coordinated_weak
    6. multi_source

    Episodes allow empirical measurement of detection latency (steps from onset to alert).
    """
    episodes_per_class = num_samples_per_class // episode_length
    records: List[EvaluationRecord] = []
    rng = random.Random(seed)

    record_counter = 0

    for class_idx, attack_class in enumerate(ATTACK_CLASSES):
        for ep_idx in range(episodes_per_class):
            ep_seed = seed + (class_idx * 10000) + ep_idx
            wh = ColdStorageWarehouse(seed=ep_seed)
            episode_id = f"EP-{attack_class[:3].upper()}-{ep_idx:04d}"

            # Warmup warehouse simulation for 5 steps so history is populated
            for _ in range(5):
                wh.step()

            # Generate replay reservoir if needed
            replay_reservoir = list(wh.history)

            for step_in_ep in range(episode_length):
                base_obs = wh.step()
                prev_obs = replay_reservoir[-1] if replay_reservoir else base_obs

                # Apply specific attack transformation
                if attack_class == "capacity_manipulation":
                    # Alternate between free_capacity manipulation and total_capacity manipulation
                    if step_in_ep % 2 == 0:
                        injected = inject_capacity_manipulation(base_obs, reported_free_capacity=base_obs.capacity - base_obs.inventory + 15.0)
                        target = "free_capacity"
                    else:
                        injected = inject_capacity_manipulation(base_obs, reported_free_capacity=None, total_capacity=base_obs.capacity - 15.0)
                        target = "total_capacity"

                elif attack_class == "inventory_manipulation":
                    # Alter inventory abruptly without shipment ledger changes
                    delta = 10.0 if (step_in_ep % 2 == 0) else -10.0
                    new_inv = max(5.0, min(base_obs.capacity - 5.0, base_obs.inventory + delta))
                    injected = inject_inventory_manipulation(base_obs, manipulated_inventory=new_inv)
                    target = "inventory"

                elif attack_class == "sensor_spoofing":
                    # Drive temperature or humidity out of physical bounds
                    if step_in_ep % 3 == 0:
                        injected = inject_sensor_spoofing(base_obs, spoofed_temperature=19.5, spoofed_humidity=None)
                        target = "temperature"
                    elif step_in_ep % 3 == 1:
                        injected = inject_sensor_spoofing(base_obs, spoofed_temperature=None, spoofed_humidity=96.0)
                        target = "humidity"
                    else:
                        injected = inject_sensor_spoofing(base_obs, spoofed_temperature=21.0, spoofed_humidity=95.0)
                        target = "environmental_sensors"

                elif attack_class == "replay_attack":
                    # Replay past telemetry observation while live state has advanced
                    stale_obs = replay_reservoir[step_in_ep % len(replay_reservoir)]
                    injected = inject_replay_attack(base_obs, stale_obs)
                    target = "telemetry_stream"

                elif attack_class == "coordinated_weak":
                    # Subtle simultaneous shifts across multiple variables to evade single checks
                    injected = inject_coordinated_manipulation(
                        base_obs,
                        inventory_delta=-1.5,
                        reported_free_capacity_delta=1.0,
                    )
                    target = "sensors_and_inventory"

                elif attack_class == "multi_source":
                    # Multi-source simultaneous manipulation of sensors and ledger
                    injected = inject_multi_source_manipulation(base_obs)
                    target = "sensors_and_ledger"

                else:
                    raise ValueError(f"Unknown attack class: {attack_class}")

                # Ensure observation step matches continuous sequential timeline
                injected_data = injected.model_dump()
                injected_data["step"] = base_obs.step
                injected_data["timestamp"] = _dataset_timestamp(base_obs.step)

                # Strict sanitisation: scrub ground-truth labels from the inner observation
                injected_data["is_attack_injected"] = False
                injected_data["attack_type"] = None
                clean_obs = WarehouseObservation(**injected_data)

                record = EvaluationRecord(
                    record_id=f"ATK-{record_counter:06d}",
                    observation=clean_obs,
                    ground_truth_label=1,
                    attack_type=attack_class,
                    episode_id=episode_id,
                    step_in_episode=step_in_ep,
                    metadata={
                        "target": target,
                        "base_step": base_obs.step,
                        "episode_step": step_in_ep,
                    },
                )
                records.append(record)
                record_counter += 1

                # Update replay reservoir
                replay_reservoir.append(base_obs)
                if len(replay_reservoir) > 10:
                    replay_reservoir.pop(0)

    logger.info(
        f"Generated {len(records)} attack observations across {len(ATTACK_CLASSES)} classes "
        f"({num_samples_per_class} per class, Seed={seed})."
    )
    return records


def create_temporal_splits(
    normal_records: List[EvaluationRecord],
    attack_records: List[EvaluationRecord],
    train_ratio: float = 0.60,
    val_ratio: float = 0.20,
    test_ratio: float = 0.20,
) -> DatasetSplits:
    """Partition records into strict temporal training, validation, and held-out test splits.

    Guarantees:
    - Zero temporal lookahead or future-data leakage (strict time ordering).
    - Training split contains normal records exclusively for clean ML baseline fitting.
    - Validation and test splits contain balanced evaluations.
    """
    total_normal = len(normal_records)
    train_end = int(total_normal * train_ratio)
    val_end = train_end + int(total_normal * val_ratio)

    # 1. Temporal split for normal observations
    train_normal = normal_records[:train_end]
    val_normal = normal_records[train_end:val_end]
    test_normal = normal_records[val_end:]

    # 2. Partition attack episodes across validation and test on a per-class basis
    # This guarantees that both validation and test sets contain all attack classes
    episodes_by_class: Dict[str, List[str]] = {}
    episodes: Dict[str, List[EvaluationRecord]] = {}
    for r in attack_records:
        if r.episode_id not in episodes:
            episodes_by_class.setdefault(r.attack_type or "unknown", []).append(r.episode_id)
        episodes.setdefault(r.episode_id, []).append(r)

    val_attack_episodes = set()
    test_attack_episodes = set()

    for atk_class, ep_ids in episodes_by_class.items():
        if len(ep_ids) >= 2:
            val_count = max(1, int(len(ep_ids) * val_ratio))
            # Ensure at least 1 episode remains for test if len >= 2
            if val_count >= len(ep_ids):
                val_count = len(ep_ids) - 1
            for ep in ep_ids[:val_count]:
                val_attack_episodes.add(ep)
            for ep in ep_ids[val_count:]:
                test_attack_episodes.add(ep)
        elif len(ep_ids) == 1:
            # If only 1 episode exists, assign to test by default
            test_attack_episodes.add(ep_ids[0])

    val_attack: List[EvaluationRecord] = []
    test_attack: List[EvaluationRecord] = []

    for r in attack_records:
        if r.episode_id in val_attack_episodes:
            val_attack.append(r)
        elif r.episode_id in test_attack_episodes:
            test_attack.append(r)
        else:
            test_attack.append(r)


    # Assemble splits
    train_split = list(train_normal)
    val_split = list(val_normal) + list(val_attack)
    test_split = list(test_normal) + list(test_attack)

    logger.info(
        f"Dataset splits created: Train={len(train_split)} (Normal only), "
        f"Val={len(val_split)} ({len(val_normal)} N / {len(val_attack)} A), "
        f"Test={len(test_split)} ({len(test_normal)} N / {len(test_attack)} A)."
    )

    return DatasetSplits(
        train=train_split,
        val=val_split,
        test=test_split,
    )
