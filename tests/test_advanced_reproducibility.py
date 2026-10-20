"""Tests for reproducible exports and the audit lifecycle verification."""

import hashlib
import json

from app.evaluation.advanced_experiments import (
    export_dataset_splits,
    run_audit_lifecycle_check,
    write_artifact_checksums,
)
from app.evaluation.dataset import (
    create_temporal_splits,
    generate_attack_dataset,
    generate_normal_dataset,
)


def _sha256(path):
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def _splits():
    normal = generate_normal_dataset(num_samples=100, seed=42)
    attacks = generate_attack_dataset(num_samples_per_class=10, seed=42, episode_length=5)
    return create_temporal_splits(
        normal_records=normal,
        attack_records=attacks,
        train_ratio=0.60,
        val_ratio=0.20,
        test_ratio=0.20,
    )


class TestDatasetExportReproducibility:
    def test_split_hashes_reproduce_across_exports(self, tmp_path):
        splits = _splits()
        first = export_dataset_splits(
            splits, tmp_path / "first", seed=42, num_normal=100, num_attack_per_class=10
        )
        second = export_dataset_splits(
            splits, tmp_path / "second", seed=42, num_normal=100, num_attack_per_class=10
        )

        for split_name in ("train", "val", "test"):
            first_split = first["splits"][split_name]
            second_split = second["splits"][split_name]
            assert first_split["sha256"] == second_split["sha256"]
            assert first_split["records"] == second_split["records"]
            path = tmp_path / "first" / "datasets" / f"{split_name}.jsonl"
            assert path.exists()
            assert _sha256(path) == first_split["sha256"]

        assert first["splits"]["train"]["attack_records"] == 0
        assert first["generation"]["seed"] == 42
        assert first["generation"]["timestamp_policy"].startswith("deterministic")
        assert first["splits"]["train"]["path"] == "datasets/train.jsonl"
        assert (tmp_path / "first" / "dataset_manifest.json").exists()

    def test_dataset_timestamps_are_deterministic(self):
        first = generate_normal_dataset(num_samples=20, seed=9)
        second = generate_normal_dataset(num_samples=20, seed=9)
        assert [r.observation.timestamp for r in first] == [r.observation.timestamp for r in second]


class TestArtifactChecksums:
    def test_checksums_cover_all_files_except_themselves(self, tmp_path):
        (tmp_path / "one.txt").write_text("one", encoding="utf-8")
        nested = tmp_path / "nested"
        nested.mkdir()
        (nested / "two.json").write_text('{"two": 2}', encoding="utf-8")

        checksums = write_artifact_checksums(tmp_path)

        assert set(checksums) == {"one.txt", "nested/two.json"}
        assert checksums["one.txt"] == _sha256(tmp_path / "one.txt")
        assert checksums["nested/two.json"] == _sha256(nested / "two.json")

        payload = json.loads((tmp_path / "artifacts_checksums.json").read_text(encoding="utf-8"))
        assert payload == checksums
        assert "artifacts_checksums.json" not in payload


class TestAuditLifecycle:
    def test_full_lifecycle_and_tamper_detection(self, tmp_path):
        payload = run_audit_lifecycle_check(tmp_path)

        assert (tmp_path / "audit_lifecycle_verification.json").exists()
        assert payload["validation_verdict"] == "PASSED"
        assert payload["unauthorized_activation_blocked"] is True
        assert payload["rejected_proposal_verdict"] == "REJECTED"
        assert payload["rejection_logged"] is True
        assert payload["rollback"]["rolled_back_proposal"] == payload["proposal_id"]
        assert payload["active_parameters_after_rollback"] == payload["baseline_parameters"]
        assert payload["audit_chain_valid"] is True
        assert payload["tamper_detected"] is True
        assert payload["tamper_error"] == "HASH_MISMATCH"
        assert payload["lifecycle_complete"] is True
        assert payload["event_types"]["HARDENING_MISS_RECORDED"] == 1
        assert payload["event_types"]["HARDENING_ROLLED_BACK"] == 1
