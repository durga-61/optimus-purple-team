"""Pipeline Evaluation Engine and Benchmark Execution Harness.

Executes continuous observation streams through the DefenderService pipeline, strictly
fits ML models on training data only, tracks per-episode detection latencies, and computes
overall, per-attack-class, and ablation metrics.
"""

from collections import defaultdict
import logging
from typing import Any, Dict, List, Optional, Tuple

from app.config import settings
from app.defender.ml_detector import MLDetector
from app.defender.service import DefenderService
from app.evaluation.dataset import (
    ATTACK_CLASSES,
    DatasetSplits,
    EvaluationRecord,
)
from app.evaluation.metrics import (
    AttackClassMetrics,
    ClassificationMetrics,
    EvaluationSummary,
    compute_classification_metrics,
    compute_latency_metrics,
)
from app.simulator.models import WarehouseObservation

logger = logging.getLogger("evaluation.evaluator")


class EvaluationEngine:
    """Executes evaluation benchmarks against DefenderService with strict training-only fitting."""

    def __init__(
        self,
        training_records: Optional[List[EvaluationRecord]] = None,
        random_state: int = 42,
    ):
        self.random_state = random_state
        self.training_records = training_records

        # Pre-fit ML Detector on training normal observations only
        self.ml_detector = self._initialize_ml_detector(training_records)
        self.service = DefenderService(ml_detector=self.ml_detector)

    def _initialize_ml_detector(
        self,
        training_records: Optional[List[EvaluationRecord]],
    ) -> MLDetector:
        """Fit ML Isolation Forest strictly on training normal baseline observations."""
        detector = MLDetector(random_state=self.random_state)
        if training_records:
            train_obs = [r.get_inference_observation() for r in training_records if r.ground_truth_label == 0]
            if len(train_obs) >= 10:
                detector.fit(train_obs)
                logger.info(f"Fitted ML detector on {len(train_obs)} verified training observations.")
        return detector

    def evaluate_split(
        self,
        records: List[EvaluationRecord],
        split_name: str = "test",
    ) -> Tuple[EvaluationSummary, List[Dict[str, Any]]]:
        """Execute the complete evaluation split through the defender pipeline."""
        logger.info(f"Starting evaluation of {len(records)} records for split '{split_name}'...")

        # Reset defender pipeline internal state before starting evaluation stream
        self.service.reset()

        detailed_results: List[Dict[str, Any]] = []

        # Tracking for overall classification
        y_true_all: List[int] = []
        y_pred_all: List[int] = []

        # Tracking for ablation configurations
        y_pred_ml: List[int] = []
        y_pred_semantic: List[int] = []
        y_pred_temporal: List[int] = []
        y_pred_structural: List[int] = []
        y_pred_sem_temp: List[int] = []
        y_pred_sem_struct: List[int] = []
        y_pred_suspicious: List[int] = []

        # Tracking for per-class metrics
        class_true: Dict[str, List[int]] = defaultdict(list)
        class_pred: Dict[str, List[int]] = defaultdict(list)

        # Tracking for episode latencies: episode_id -> first detected step_in_episode (or None)
        episode_latencies: Dict[str, Optional[int]] = {}
        episode_classes: Dict[str, str] = {}

        for idx, record in enumerate(records):
            clean_obs = record.get_inference_observation()
            analysis = self.service.analyze(clean_obs)

            decision = analysis.decision
            ml = analysis.ml
            semantic = analysis.semantic
            temporal = analysis.temporal
            structural = analysis.structural

            # Primary detection criterion:
            # Operational alert generated or classification escalated to potential/coordinated attack
            is_detected = (
                decision.classification in ("POTENTIAL_ATTACK", "COORDINATED_ATTACK")
                or len(analysis.alerts) > 0
            )
            pred_int = 1 if is_detected else 0

            # Sensitive/Triage escalation criterion (includes SUSPICIOUS states)
            is_suspicious_or_alert = (
                is_detected or decision.classification == "SUSPICIOUS"
            )
            pred_suspicious_int = 1 if is_suspicious_or_alert else 0

            # Genuine layer ablation indicators
            pred_ml_int = 1 if ml.is_anomaly else 0
            pred_semantic_int = 1 if len(semantic.violated_constraints) > 0 else 0
            pred_temporal_int = 1 if temporal.status in ("ELEVATED", "ESCALATING") else 0
            pred_structural_int = 1 if structural.status in ("CORRELATED", "MULTI_SOURCE") else 0
            pred_sem_temp_int = 1 if (pred_semantic_int == 1 or pred_temporal_int == 1) else 0
            pred_sem_struct_int = 1 if (pred_semantic_int == 1 or pred_structural_int == 1) else 0

            # Accumulate overall
            y_true_all.append(record.ground_truth_label)
            y_pred_all.append(pred_int)

            y_pred_ml.append(pred_ml_int)
            y_pred_semantic.append(pred_semantic_int)
            y_pred_temporal.append(pred_temporal_int)
            y_pred_structural.append(pred_structural_int)
            y_pred_sem_temp.append(pred_sem_temp_int)
            y_pred_sem_struct.append(pred_sem_struct_int)
            y_pred_suspicious.append(pred_suspicious_int)

            # Attack episode latency tracking
            if record.ground_truth_label == 1:
                ep_id = record.episode_id
                atk_type = record.attack_type or "unknown"
                episode_classes[ep_id] = atk_type

                if ep_id not in episode_latencies:
                    episode_latencies[ep_id] = None

                if is_detected and episode_latencies[ep_id] is None:
                    episode_latencies[ep_id] = record.step_in_episode

                class_true[atk_type].append(1)
                class_pred[atk_type].append(pred_int)
            else:
                # Normal samples belong to normal baseline
                class_true["normal"].append(0)
                class_pred["normal"].append(pred_int)

            # Record detailed prediction row
            detailed_results.append({
                "record_id": record.record_id,
                "step": clean_obs.step,
                "episode_id": record.episode_id,
                "step_in_episode": record.step_in_episode,
                "ground_truth_label": record.ground_truth_label,
                "attack_type": record.attack_type or "normal",
                "predicted_label": pred_int,
                "pred_ml": pred_ml_int,
                "pred_semantic": pred_semantic_int,
                "pred_temporal": pred_temporal_int,
                "pred_structural": pred_structural_int,
                "pred_joint_with_suspicious": pred_suspicious_int,
                "classification": decision.classification,
                "risk_score": decision.risk_score,
                "integrity_score": decision.integrity_score,
                "ml_score": ml.anomaly_score,
                "ml_is_anomaly": ml.is_anomaly,
                "semantic_violations": len(semantic.violated_constraints),
                "temporal_score": temporal.temporal_score,
                "temporal_status": temporal.status,
                "structural_score": structural.structural_score,
                "structural_status": structural.status,
                "alerts_count": len(analysis.alerts),
            })

            if (idx + 1) % 2000 == 0:
                logger.info(f"Processed {idx + 1}/{len(records)} evaluation records...")

        # 1. Overall Metrics
        overall_metrics = compute_classification_metrics(y_true_all, y_pred_all)

        # 2. Overall Latency Metrics
        all_latencies = list(episode_latencies.values())
        overall_latency = compute_latency_metrics(all_latencies, len(episode_latencies))

        # 3. Per-Attack-Class Metrics
        per_class_metrics: Dict[str, AttackClassMetrics] = {}
        for atk_class in ATTACK_CLASSES:
            c_true = class_true[atk_class]
            c_pred = class_pred[atk_class]

            # In attack-only subset, precision requires normal negatives; we evaluate against normal FPR
            # Detection rate = TP / (TP + FN) = sum(c_pred) / len(c_pred)
            total_atk_samples = len(c_true)
            detected_atk_samples = sum(c_pred)
            det_rate = detected_atk_samples / total_atk_samples if total_atk_samples > 0 else 0.0

            # Calculate class-specific precision incorporating normal false positives
            normal_fp = sum(1 for yt, yp in zip(class_true["normal"], class_pred["normal"]) if yt == 0 and yp == 1)
            class_precision = (
                detected_atk_samples / (detected_atk_samples + normal_fp)
                if (detected_atk_samples + normal_fp) > 0
                else 0.0
            )

            class_f1 = (
                2.0 * (class_precision * det_rate) / (class_precision + det_rate)
                if (class_precision + det_rate) > 0
                else 0.0
            )

            # Class latency
            class_ep_latencies = [
                lat for ep_id, lat in episode_latencies.items()
                if episode_classes.get(ep_id) == atk_class
            ]
            class_total_episodes = len(class_ep_latencies)
            class_latency_metric = compute_latency_metrics(class_ep_latencies, class_total_episodes)

            per_class_metrics[atk_class] = AttackClassMetrics(
                attack_class=atk_class,
                total_samples=total_atk_samples,
                detected_samples=detected_atk_samples,
                detection_rate=det_rate,
                precision=class_precision,
                recall=det_rate,
                f1_score=class_f1,
                latency=class_latency_metric,
            )

        # 4. Stage Ablation Metrics
        ablation_metrics: Dict[str, ClassificationMetrics] = {
            "ml_only": compute_classification_metrics(y_true_all, y_pred_ml),
            "semantic_only": compute_classification_metrics(y_true_all, y_pred_semantic),
            "temporal_only": compute_classification_metrics(y_true_all, y_pred_temporal),
            "structural_only": compute_classification_metrics(y_true_all, y_pred_structural),
            "semantic_plus_temporal": compute_classification_metrics(y_true_all, y_pred_sem_temp),
            "semantic_plus_structural": compute_classification_metrics(y_true_all, y_pred_sem_struct),
            "joint_decision": overall_metrics,
            "joint_with_suspicious": compute_classification_metrics(y_true_all, y_pred_suspicious),
        }

        summary = EvaluationSummary(
            split_name=split_name,
            overall=overall_metrics,
            latency=overall_latency,
            per_class=per_class_metrics,
            ablation=ablation_metrics,
        )

        logger.info(
            f"Evaluation complete for '{split_name}': Detection Rate={overall_metrics.detection_rate:.4f}, "
            f"FPR={overall_metrics.false_positive_rate:.4f}, Precision={overall_metrics.precision:.4f}, "
            f"F1={overall_metrics.f1_score:.4f}, Mean Latency={overall_latency.mean_latency:.2f} steps."
        )

        return summary, detailed_results
