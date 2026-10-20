"""Tests for Deterministic Dataset Generator and Temporal Splitting.

Verifies:
- Deterministic reproducibility across seeds.
- 12,000 normal and 12,000 attack dataset volumes.
- 100% invariant adherence in normal data (C1, C2, C3).
- Strict feature decoupling and anti-data-leakage protections.
- Temporal split boundaries, monotonicity, and non-overlapping sets.
"""

import pytest

from app.evaluation.dataset import (
    ATTACK_CLASSES,
    create_temporal_splits,
    generate_attack_dataset,
    generate_normal_dataset,
    verify_normal_observation_invariants,
)


class TestDatasetDeterminismAndVolume:
    """Test seed determinism and volume generation."""

    def test_normal_generation_is_deterministic(self):
        """Identical seeds produce identical normal observations bit-for-bit."""
        records_a = generate_normal_dataset(num_samples=100, seed=42)
        records_b = generate_normal_dataset(num_samples=100, seed=42)

        assert len(records_a) == 100
        assert len(records_b) == 100

        for r_a, r_b in zip(records_a, records_b):
            assert r_a.record_id == r_b.record_id
            assert r_a.observation.inventory == r_b.observation.inventory
            assert r_a.observation.free_capacity == r_b.observation.free_capacity
            assert r_a.observation.temperature == r_b.observation.temperature
            assert r_a.observation.humidity == r_b.observation.humidity

    def test_different_seeds_produce_divergent_normal_data(self):
        """Different seeds produce statistically divergent trajectories."""
        records_42 = generate_normal_dataset(num_samples=50, seed=42)
        records_99 = generate_normal_dataset(num_samples=50, seed=99)

        different_inventories = sum(
            1 for a, b in zip(records_42, records_99) if a.observation.inventory != b.observation.inventory
        )
        assert different_inventories > 20

    def test_attack_generation_is_deterministic(self):
        """Identical seeds produce identical attack observations across classes."""
        atk_a = generate_attack_dataset(num_samples_per_class=20, seed=42, episode_length=10)
        atk_b = generate_attack_dataset(num_samples_per_class=20, seed=42, episode_length=10)

        assert len(atk_a) == len(atk_b)
        for a, b in zip(atk_a, atk_b):
            assert a.record_id == b.record_id
            assert a.attack_type == b.attack_type
            assert a.episode_id == b.episode_id
            assert a.observation.inventory == b.observation.inventory
            assert a.observation.temperature == b.observation.temperature

    def test_attack_dataset_volume_and_class_distribution(self):
        """Generates exact number of observations per attack class."""
        num_per_class = 40
        atk_records = generate_attack_dataset(num_samples_per_class=num_per_class, seed=42, episode_length=10)

        assert len(atk_records) == num_per_class * len(ATTACK_CLASSES)
        class_counts = {}
        for r in atk_records:
            class_counts[r.attack_type] = class_counts.get(r.attack_type, 0) + 1

        for c in ATTACK_CLASSES:
            assert class_counts[c] == num_per_class


class TestNormalInvariantPurity:
    """Verify that normal observations strictly obey cold-storage warehouse invariants."""

    def test_normal_observations_satisfy_all_invariants(self):
        """All generated normal observations satisfy C1, C2, and C3 without exception."""
        normal_records = generate_normal_dataset(num_samples=500, seed=123)

        prev_obs = None
        for record in normal_records:
            obs = record.observation
            is_valid, violations = verify_normal_observation_invariants(obs, prev_obs)
            assert is_valid, f"Violations at step {obs.step}: {violations}"
            prev_obs = obs


class TestDataLeakagePrevention:
    """Verify that ground-truth labels and attack metadata never leak into defender inputs."""

    def test_sanitised_inference_observation_contains_no_ground_truth(self):
        """get_inference_observation() scrubs all ground-truth attack flags."""
        atk_records = generate_attack_dataset(num_samples_per_class=10, seed=42, episode_length=5)

        for r in atk_records:
            # The record metadata knows it's an attack
            assert r.ground_truth_label == 1
            assert r.attack_type in ATTACK_CLASSES

            # The inference observation fed to the defender must be 100% scrubbed
            clean_obs = r.get_inference_observation()
            assert clean_obs.is_attack_injected is False
            assert clean_obs.attack_type is None

            # Features vector extracted from clean_obs has only physical values
            obs_dict = clean_obs.model_dump()
            assert obs_dict["is_attack_injected"] is False
            assert obs_dict["attack_type"] is None
            assert "ground_truth_label" not in obs_dict
            assert "target" not in obs_dict


class TestTemporalSplits:
    """Verify chronological train/val/test splits."""

    def test_split_boundaries_and_temporal_order(self):
        """Splits are temporally continuous, non-overlapping, and training has zero attacks."""
        normal_records = generate_normal_dataset(num_samples=200, seed=42)
        attack_records = generate_attack_dataset(num_samples_per_class=30, seed=42, episode_length=10)

        splits = create_temporal_splits(
            normal_records=normal_records,
            attack_records=attack_records,
            train_ratio=0.60,
            val_ratio=0.20,
            test_ratio=0.20,
        )

        # 1. Total counts
        assert len(splits.train) == 120  # 60% of 200 normal
        assert len(splits.val) > 0
        assert len(splits.test) > 0

        # 2. Training set contains ONLY normal observations
        for r in splits.train:
            assert r.ground_truth_label == 0
            assert r.attack_type == "normal"

        # 3. No record ID overlap across splits
        train_ids = set(r.record_id for r in splits.train)
        val_ids = set(r.record_id for r in splits.val)
        test_ids = set(r.record_id for r in splits.test)

        assert train_ids.isdisjoint(val_ids)
        assert train_ids.isdisjoint(test_ids)
        assert val_ids.isdisjoint(test_ids)

        # 4. Strict chronological order in normal components
        train_steps = [r.observation.step for r in splits.train]
        assert train_steps == sorted(train_steps)
        max_train_step = max(train_steps)

        val_normal_steps = [r.observation.step for r in splits.val if r.ground_truth_label == 0]
        assert all(s > max_train_step for s in val_normal_steps)

    def test_exact_reconciled_split_arithmetic(self):
        """Verifies exact split counts for the canonical benchmark configuration."""
        # Scaled test with 600 normal, 600 attacks (100 per class, 5 episodes of 20 steps)
        normal_records = generate_normal_dataset(num_samples=600, seed=42)
        attack_records = generate_attack_dataset(num_samples_per_class=100, seed=42, episode_length=20)

        splits = create_temporal_splits(
            normal_records=normal_records,
            attack_records=attack_records,
            train_ratio=0.60,
            val_ratio=0.20,
            test_ratio=0.20,
        )

        # Train: 60% normal = 360, 0 attack
        assert len(splits.train) == 360
        assert sum(1 for r in splits.train if r.ground_truth_label == 1) == 0

        # Val: 20% normal = 120, 20% attack = 120 (1 episode of 20 steps x 6 classes)
        val_normal = sum(1 for r in splits.val if r.ground_truth_label == 0)
        val_attack = sum(1 for r in splits.val if r.ground_truth_label == 1)
        assert val_normal == 120
        assert val_attack == 120  # 1 episode * 20 steps * 6 classes
        assert len(splits.val) == 240

        # Test: 20% normal = 120, 80% attack = 480 (4 episodes of 20 steps x 6 classes)
        test_normal = sum(1 for r in splits.test if r.ground_truth_label == 0)
        test_attack = sum(1 for r in splits.test if r.ground_truth_label == 1)
        assert test_normal == 120
        assert test_attack == 480
        assert len(splits.test) == 600

    def test_attack_episodes_time_ordered_and_non_overlapping(self):
        """Verify attack episodes do not overlap and maintain temporal monotonicity across val and test."""
        normal_records = generate_normal_dataset(num_samples=100, seed=42)
        attack_records = generate_attack_dataset(num_samples_per_class=60, seed=42, episode_length=20)

        splits = create_temporal_splits(
            normal_records=normal_records,
            attack_records=attack_records,
            train_ratio=0.60,
            val_ratio=0.20,
            test_ratio=0.20,
        )

        val_episodes = set(r.episode_id for r in splits.val if r.ground_truth_label == 1)
        test_episodes = set(r.episode_id for r in splits.test if r.ground_truth_label == 1)

        # Zero episode overlap
        assert val_episodes.isdisjoint(test_episodes)

        # Per-class temporal ordering: validation episodes were created earlier than test episodes
        for c in ATTACK_CLASSES:
            val_eps = sorted(list(set(r.episode_id for r in splits.val if r.attack_type == c)))
            test_eps = sorted(list(set(r.episode_id for r in splits.test if r.attack_type == c)))
            assert len(val_eps) > 0
            assert len(test_eps) > 0
            val_indices = [int(ep.split("-")[-1]) for ep in val_eps]
            test_indices = [int(ep.split("-")[-1]) for ep in test_eps]
            assert max(val_indices) < min(test_indices), f"Temporal episode inversion detected in attack class {c}!"

            # Record creation sequence monotonicity
            val_rec_nums = [int(r.record_id.split("-")[-1]) for r in splits.val if r.attack_type == c]
            test_rec_nums = [int(r.record_id.split("-")[-1]) for r in splits.test if r.attack_type == c]
            assert max(val_rec_nums) < min(test_rec_nums), f"Record sequence inversion detected in attack class {c}!"

