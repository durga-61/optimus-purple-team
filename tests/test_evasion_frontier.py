"""Tests for scaled-attack evasion-frontier generation and exports."""

import csv
import json
from pathlib import Path

from app.defender.ml_detector import MLDetector
from app.evaluation.dataset import generate_normal_dataset
from app.evaluation.evasion_frontier import (
    FRONTIER_ATTACK_CLASSES,
    PipelinePredictor,
    compute_frontier,
    export_evasion_frontier,
    generate_frontier_records,
    summarise_frontier,
)


class AlwaysDetect:
    def predict(self, observations):
        return [1] * len(observations), [0.9] * len(observations)


class NeverDetect:
    def predict(self, observations):
        return [0] * len(observations), [0.1] * len(observations)


class TestFrontierGeneration:
    def test_generates_scaled_episodes_for_every_attack_class(self):
        records = generate_frontier_records(
            seed=3,
            strengths=(0.1, 1.0),
            episodes_per_class=1,
            episode_length=2,
        )

        assert len(records) == len(FRONTIER_ATTACK_CLASSES) * 2 * 1 * 2
        assert {record.attack_type for record in records} == set(FRONTIER_ATTACK_CLASSES)
        assert {record.metadata["strength"] for record in records} == {0.1, 1.0}
        assert all(record.ground_truth_label == 1 for record in records)
        assert all(record.observation.is_attack_injected is False for record in records)
        assert all(record.observation.attack_type is None for record in records)

    def test_generation_is_deterministic(self):
        first = generate_frontier_records(
            seed=5, strengths=(0.25,), episodes_per_class=1, episode_length=3
        )
        second = generate_frontier_records(
            seed=5, strengths=(0.25,), episodes_per_class=1, episode_length=3
        )

        assert [r.record_id for r in first] == [r.record_id for r in second]
        for left, right in zip(first, second):
            assert left.observation.inventory == right.observation.inventory
            assert left.observation.temperature == right.observation.temperature
            assert left.observation.timestamp == right.observation.timestamp


class TestFrontierComputation:
    def _records(self):
        return generate_frontier_records(
            seed=11,
            strengths=(0.25, 1.0),
            episodes_per_class=1,
            episode_length=2,
        )

    def test_compute_frontier_covers_every_strength_class_and_config(self):
        records = self._records()
        frontier = compute_frontier(
            records,
            {"detect_all": AlwaysDetect(), "detect_none": NeverDetect()},
        )

        expected_rows = 2 * 2 * (len(FRONTIER_ATTACK_CLASSES) + 1)
        assert len(frontier["rows"]) == expected_rows
        assert frontier["configs"] == ["detect_all", "detect_none"]
        assert frontier["attack_classes"] == list(FRONTIER_ATTACK_CLASSES)
        assert "ALL" in {row["attack_class"] for row in frontier["rows"]}

        for row in frontier["rows"]:
            if row["config"] == "detect_all":
                assert row["detection_rate"] == 1.0
                assert row["evasion_rate"] == 0.0
            else:
                assert row["detection_rate"] == 0.0
                assert row["evasion_rate"] == 1.0

    def test_summary_reports_mean_and_full_strength_evasion(self):
        frontier = compute_frontier(
            self._records(),
            {"detect_all": AlwaysDetect(), "detect_none": NeverDetect()},
        )
        summary = summarise_frontier(frontier)

        assert summary["detect_all"]["mean_evasion_across_strengths"] == 0.0
        assert summary["detect_all"]["evasion_at_full_strength"] == 0.0
        assert summary["detect_none"]["mean_evasion_across_strengths"] == 1.0
        assert summary["detect_none"]["evasion_at_full_strength"] == 1.0

    def test_export_writes_csv_json_and_charts(self, tmp_path):
        frontier = compute_frontier(
            self._records(),
            {"detect_none": NeverDetect()},
        )
        exported = export_evasion_frontier(frontier, tmp_path)

        assert (tmp_path / "evasion_frontier.csv").exists()
        assert (tmp_path / "evasion_frontier.json").exists()
        assert exported["evasion_frontier_csv"].endswith("evasion_frontier.csv")
        assert exported["evasion_frontier_json"].endswith("evasion_frontier.json")

        with open(tmp_path / "evasion_frontier.csv", newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        assert len(rows) == len(frontier["rows"])

        payload = json.loads((tmp_path / "evasion_frontier.json").read_text(encoding="utf-8"))
        assert payload["summary"]["detect_none"]["mean_evasion_across_strengths"] == 1.0

        for key in ("evasion_frontier_chart", "evasion_frontier_by_class_chart"):
            if key in exported:
                assert (tmp_path / Path(exported[key]).name).exists()


class TestPipelinePredictor:
    def test_replays_observations_through_fresh_pipeline(self):
        normal = generate_normal_dataset(num_samples=30, seed=13)
        detector = MLDetector(random_state=13)
        detector.fit([record.get_inference_observation() for record in normal[:20]])

        observations = [record.get_inference_observation() for record in normal[20:]]
        predictions, scores = PipelinePredictor(detector).predict(observations)

        assert len(predictions) == len(observations)
        assert len(scores) == len(observations)
        assert set(predictions).issubset({0, 1})
        assert all(0.0 <= score <= 1.0 for score in scores)
