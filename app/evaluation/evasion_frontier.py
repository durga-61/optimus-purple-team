"""Systematic evasion-frontier experiments for OPTIMUS and baselines.

Attack magnitude is scaled from subtle to overt, then detection is measured for
the static detector, adaptive fusion, mined invariants, the combined system,
One-Class SVM, and PCA.  Evasion rate is simply ``1 - detection_rate`` over
confirmed malicious observations.
"""

import csv
from datetime import datetime, timedelta, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

from app.defender.decision import JointDecisionEngine
from app.defender.semantic import SemanticEngine
from app.defender.structural import StructuralEngine
from app.defender.temporal import TemporalEngine
from app.evaluation.dataset import EvaluationRecord
from app.simulator.models import WarehouseObservation
from app.simulator.scenarios import (
    inject_capacity_manipulation,
    inject_coordinated_manipulation,
    inject_inventory_manipulation,
    inject_replay_attack,
    inject_sensor_spoofing,
)
from app.simulator.warehouse import ColdStorageWarehouse

logger = logging.getLogger("evaluation.evasion_frontier")

ATTACK_STRENGTHS: Tuple[float, ...] = (0.10, 0.25, 0.40, 0.60, 0.80, 1.00)
FRONTIER_ATTACK_CLASSES: Tuple[str, ...] = (
    "capacity_manipulation",
    "inventory_manipulation",
    "sensor_spoofing",
    "replay_attack",
    "coordinated_weak",
    "multi_source",
)


def _clean_record(
    observation: WarehouseObservation,
    record_id: str,
    attack_class: str,
    strength: float,
    episode_id: str,
    step_in_episode: int,
) -> EvaluationRecord:
    data = observation.model_dump()
    data["is_attack_injected"] = False
    data["attack_type"] = None
    data["timestamp"] = (
        datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=observation.step)
    ).isoformat()
    return EvaluationRecord(
        record_id=record_id,
        observation=WarehouseObservation(**data),
        ground_truth_label=1,
        attack_type=attack_class,
        episode_id=episode_id,
        step_in_episode=step_in_episode,
        metadata={"strength": strength, "target": attack_class},
    )


def generate_frontier_records(
    seed: int = 42,
    strengths: Sequence[float] = ATTACK_STRENGTHS,
    episodes_per_class: int = 8,
    episode_length: int = 8,
) -> List[EvaluationRecord]:
    """Generate scaled attack episodes from subtle to overt."""
    records: List[EvaluationRecord] = []
    counter = 0
    for class_index, attack_class in enumerate(FRONTIER_ATTACK_CLASSES):
        for strength in strengths:
            for episode in range(episodes_per_class):
                warehouse = ColdStorageWarehouse(seed=seed + class_index * 10000 + int(strength * 1000) + episode)
                for _ in range(5):
                    warehouse.step()
                episode_id = f"FR-{attack_class[:3].upper()}-{int(strength * 100):03d}-{episode:03d}"

                for step_in_episode in range(episode_length):
                    base = warehouse.step()

                    if attack_class == "capacity_manipulation":
                        injected = inject_capacity_manipulation(
                            base,
                            reported_free_capacity=base.free_capacity + 2.0 * strength,
                        )
                    elif attack_class == "inventory_manipulation":
                        delta = 4.0 * strength * (1.0 if step_in_episode % 2 == 0 else -1.0)
                        injected = inject_inventory_manipulation(
                            base,
                            manipulated_inventory=max(0.0, min(base.capacity, base.inventory + delta)),
                        )
                    elif attack_class == "sensor_spoofing":
                        injected = inject_sensor_spoofing(
                            base,
                            spoofed_temperature=base.temperature + 15.0 * strength,
                            spoofed_humidity=min(99.0, base.humidity + 25.0 * strength),
                        )
                    elif attack_class == "replay_attack":
                        lag = max(1, int(round(10 * strength)))
                        available = max(0, len(warehouse.history) - 1)
                        stale = warehouse.history[-1 - min(lag, available)]
                        injected = inject_replay_attack(base, stale)
                    elif attack_class == "coordinated_weak":
                        injected = inject_coordinated_manipulation(
                            base,
                            inventory_delta=-1.5 * strength,
                            reported_free_capacity_delta=1.0 * strength,
                        )
                    elif attack_class == "multi_source":
                        data = base.model_dump()
                        data["inventory"] = max(0.0, round(base.inventory - 4.0 * strength, 2))
                        data["temperature"] = round(base.temperature + 6.0 * strength, 2)
                        data["inbound"] = 0.0
                        data["outbound"] = 0.0
                        data["is_attack_injected"] = True
                        data["attack_type"] = "multi_source_manipulation"
                        injected = WarehouseObservation(**data)
                    else:
                        raise ValueError(f"Unknown attack class {attack_class}")

                    data = injected.model_dump()
                    data["step"] = base.step
                    injected = WarehouseObservation(**data)
                    records.append(
                        _clean_record(
                            injected,
                            record_id=f"FR-{counter:07d}",
                            attack_class=attack_class,
                            strength=float(strength),
                            episode_id=episode_id,
                            step_in_episode=step_in_episode,
                        )
                    )
                    counter += 1
    logger.info("Generated %d evasion-frontier observations.", len(records))
    return records


class PipelinePredictor:
    """Replays an episode through a fresh OPTIMUS pipeline configuration."""

    def __init__(
        self,
        ml_detector: Any,
        weights: Optional[Dict[str, float]] = None,
        active_invariants: Optional[Sequence[Any]] = None,
    ):
        self.ml_detector = ml_detector
        self.weights = dict(weights) if weights else None
        self.active_invariants = list(active_invariants or [])

    def predict(self, observations: Sequence[WarehouseObservation]) -> Tuple[List[int], List[float]]:
        semantic = SemanticEngine()
        for invariant in self.active_invariants:
            semantic.add_invariant(invariant)
        temporal = TemporalEngine()
        structural = StructuralEngine()
        decision = JointDecisionEngine()
        if self.weights:
            decision.update_weights(self.weights)

        predictions: List[int] = []
        scores: List[float] = []
        previous = None
        history: List[WarehouseObservation] = []
        for observation in observations:
            ml = self.ml_detector.analyze(observation)
            semantic_result = semantic.analyze(observation, previous_obs=previous, history=history)
            structural_result = structural.analyze(semantic_result=semantic_result, ml_result=ml)
            temporal_result = temporal.update(
                step=observation.step,
                semantic_result=semantic_result,
                ml_result=ml,
                structural_result=structural_result,
            )
            result = decision.decide(
                ml=ml,
                semantic=semantic_result,
                temporal=temporal_result,
                structural=structural_result,
            )
            predictions.append(int(result.classification in ("POTENTIAL_ATTACK", "COORDINATED_ATTACK")))
            scores.append(float(result.risk_score))
            previous = observation
            history.append(observation)
            if len(history) > 100:
                history.pop(0)
        return predictions, scores


class BaselinePredictor:
    """Adapter exposing calibrated One-Class SVM / PCA detectors to the frontier."""

    def __init__(self, detector: Any, threshold: Optional[float] = None):
        self.detector = detector
        self.threshold = threshold if threshold is not None else detector.threshold

    def predict(self, observations: Sequence[WarehouseObservation]) -> Tuple[List[int], List[float]]:
        scores = self.detector.score(observations)
        predictions = (scores >= self.threshold).astype(int).tolist()
        return predictions, scores.tolist()


def compute_frontier(
    records: Sequence[EvaluationRecord],
    configs: Dict[str, Any],
) -> Dict[str, Any]:
    """Evaluate all configurations over every strength/class cell."""
    groups: Dict[Tuple[float, str], List[Any]] = {}
    for record in records:
        strength = float(record.metadata.get("strength", 1.0))
        key = (strength, record.episode_id)
        groups.setdefault(key, []).append(record)

    rows: List[Dict[str, Any]] = []
    for config_name, predictor in configs.items():
        cells: Dict[Tuple[float, str], Dict[str, float]] = {}
        for (strength, episode_id), episode_records in groups.items():
            observations = [record.get_inference_observation() for record in episode_records]
            predictions, scores = predictor.predict(observations)
            attack_class = episode_records[0].attack_type or "unknown"
            for key in ((strength, attack_class), (strength, "ALL")):
                cell = cells.setdefault(key, {"total": 0, "detected": 0, "score_sum": 0.0})
                cell["total"] += len(predictions)
                cell["detected"] += int(sum(predictions))
                cell["score_sum"] += float(sum(scores))

        for (strength, attack_class), cell in sorted(cells.items()):
            total = int(cell["total"])
            detected = int(cell["detected"])
            detection_rate = detected / total if total else 0.0
            rows.append(
                {
                    "config": config_name,
                    "strength": round(strength, 3),
                    "attack_class": attack_class,
                    "total": total,
                    "detected": detected,
                    "detection_rate": round(detection_rate, 4),
                    "evasion_rate": round(1.0 - detection_rate, 4),
                    "mean_score": round(cell["score_sum"] / total, 4) if total else 0.0,
                }
            )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "strengths": sorted({row["strength"] for row in rows}),
        "configs": list(configs.keys()),
        "attack_classes": list(FRONTIER_ATTACK_CLASSES),
        "rows": rows,
    }


def summarise_frontier(frontier: Dict[str, Any]) -> Dict[str, Any]:
    """Mean overall evasion by config and hardest class at full strength."""
    summary: Dict[str, Any] = {}
    for config in frontier["configs"]:
        all_rows = [
            row for row in frontier["rows"] if row["config"] == config and row["attack_class"] == "ALL"
        ]
        if not all_rows:
            continue
        summary[config] = {
            "mean_evasion_across_strengths": round(
                float(np.mean([row["evasion_rate"] for row in all_rows])), 4
            ),
            "evasion_at_full_strength": next(
                (row["evasion_rate"] for row in all_rows if row["strength"] == max(frontier["strengths"])),
                None,
            ),
        }
    return summary


def export_evasion_frontier(frontier: Dict[str, Any], output_dir: str | Path) -> Dict[str, str]:
    """Write CSV/JSON artifacts and comparative PNG charts."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    exported: Dict[str, str] = {}

    csv_path = output / "evasion_frontier.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "config",
                "strength",
                "attack_class",
                "total",
                "detected",
                "detection_rate",
                "evasion_rate",
                "mean_score",
            ],
        )
        writer.writeheader()
        writer.writerows(frontier["rows"])
    exported["evasion_frontier_csv"] = str(csv_path)

    json_path = output / "evasion_frontier.json"
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump({**frontier, "summary": summarise_frontier(frontier)}, handle, indent=2)
    exported["evasion_frontier_json"] = str(json_path)

    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        overall_path = output / "evasion_frontier.png"
        fig, ax = plt.subplots(figsize=(9, 5.5))
        for config in frontier["configs"]:
            series = [
                row
                for row in frontier["rows"]
                if row["config"] == config and row["attack_class"] == "ALL"
            ]
            if not series:
                continue
            series.sort(key=lambda row: row["strength"])
            ax.plot(
                [row["strength"] for row in series],
                [row["evasion_rate"] * 100 for row in series],
                marker="o",
                label=config,
            )
        ax.set_xlabel("Attack magnitude (scaled)")
        ax.set_ylabel("Evasion rate (%)")
        ax.set_title("OPTIMUS Evasion Frontier vs. Baselines")
        ax.set_ylim(0, 105)
        ax.grid(True, linestyle="--", alpha=0.5)
        ax.legend(fontsize=8)
        plt.tight_layout()
        plt.savefig(overall_path, dpi=200)
        plt.close()
        exported["evasion_frontier_chart"] = str(overall_path)

        combined_name = next(
            (name for name in frontier["configs"] if "combined" in name),
            frontier["configs"][0] if frontier["configs"] else None,
        )
        if combined_name:
            class_path = output / "evasion_frontier_by_class.png"
            fig, axes = plt.subplots(2, 3, figsize=(12, 7), sharex=True, sharey=True)
            for axis, attack_class in zip(axes.flat, FRONTIER_ATTACK_CLASSES):
                series = [
                    row
                    for row in frontier["rows"]
                    if row["config"] == combined_name and row["attack_class"] == attack_class
                ]
                series.sort(key=lambda row: row["strength"])
                axis.plot(
                    [row["strength"] for row in series],
                    [row["evasion_rate"] * 100 for row in series],
                    marker="o",
                    color="#1f77b4",
                )
                axis.set_title(attack_class.replace("_", " "), fontsize=9)
                axis.set_ylim(0, 105)
                axis.grid(True, linestyle="--", alpha=0.4)
            for axis in axes.flat[len(FRONTIER_ATTACK_CLASSES):]:
                axis.axis("off")
            fig.suptitle(f"Evasion by Attack Class — {combined_name}")
            fig.text(0.5, 0.02, "Attack magnitude (scaled)", ha="center")
            fig.text(0.02, 0.5, "Evasion rate (%)", va="center", rotation=90)
            plt.tight_layout(rect=(0.03, 0.03, 1, 0.95))
            plt.savefig(class_path, dpi=200)
            plt.close()
            exported["evasion_frontier_by_class_chart"] = str(class_path)
    except Exception as exc:  # Charting must not block the experiment.
        logger.warning("Could not render evasion frontier charts: %s", exc)

    return exported
