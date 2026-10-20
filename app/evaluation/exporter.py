"""CSV Exporter, Visualization Generator, and Replay Limitation Documentation for Benchmarks."""

import csv
import logging
import os
from pathlib import Path
from typing import Any, Dict, List

from app.evaluation.metrics import EvaluationSummary

logger = logging.getLogger("evaluation.exporter")


class BenchmarkExporter:
    """Exports benchmark evaluation artifacts including CSV tables, PNG charts, and documentation."""

    def __init__(self, output_dir: str = "evaluation_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export_all(
        self,
        summary: EvaluationSummary,
        detailed_predictions: List[Dict[str, Any]],
        generate_charts: bool = True,
    ) -> Dict[str, str]:
        """Export all CSV summaries, prediction ledgers, charts, and documentation."""
        exported_files = {}

        # 1. Summary CSV
        summary_csv_path = self.output_dir / "benchmark_summary.csv"
        self._export_summary_csv(summary, summary_csv_path)
        exported_files["summary_csv"] = str(summary_csv_path)

        # 2. Per-Class Metrics CSV
        class_csv_path = self.output_dir / "per_class_metrics.csv"
        self._export_per_class_csv(summary, class_csv_path)
        exported_files["per_class_csv"] = str(class_csv_path)

        # 3. Ablation Metrics CSV
        ablation_csv_path = self.output_dir / "ablation_metrics.csv"
        self._export_ablation_csv(summary, ablation_csv_path)
        exported_files["ablation_csv"] = str(ablation_csv_path)

        # 4. Detailed Predictions CSV
        predictions_csv_path = self.output_dir / "detailed_predictions.csv"
        self._export_predictions_csv(detailed_predictions, predictions_csv_path)
        exported_files["detailed_predictions_csv"] = str(predictions_csv_path)

        # 5. Replay Attack Limitations Document
        replay_doc_path = self.output_dir / "REPLAY_LIMITATIONS.md"
        self._export_replay_limitations_doc(summary, replay_doc_path)
        exported_files["replay_limitations_doc"] = str(replay_doc_path)

        # 6. Generate Charts (Matplotlib)
        if generate_charts:
            chart_paths = self._generate_charts(summary)
            exported_files.update(chart_paths)

        logger.info(f"Exported all evaluation artifacts to {self.output_dir}")
        return exported_files

    def _export_summary_csv(self, summary: EvaluationSummary, path: Path) -> None:
        ov = summary.overall
        lat = summary.latency
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Metric", "Value", "Description"])
            writer.writerow(["Split Name", summary.split_name, "Evaluation data split"])
            writer.writerow(["Total Samples", ov.total, "Total observations evaluated"])
            writer.writerow(["True Positives (TP)", ov.tp, "Attacks correctly detected"])
            writer.writerow(["False Positives (FP)", ov.fp, "Normal observations incorrectly flagged"])
            writer.writerow(["True Negatives (TN)", ov.tn, "Normal observations correctly cleared"])
            writer.writerow(["False Negatives (FN)", ov.fn, "Attacks missed by defender"])
            writer.writerow(["Detection Rate (Recall)", f"{ov.detection_rate:.4f}", "TP / (TP + FN)"])
            writer.writerow(["False Positive Rate (FPR)", f"{ov.false_positive_rate:.4f}", "FP / (FP + TN)"])
            writer.writerow(["False Negative Rate (FNR)", f"{ov.false_negative_rate:.4f}", "FN / (TP + FN)"])
            writer.writerow(["Precision", f"{ov.precision:.4f}", "TP / (TP + FP)"])
            writer.writerow(["F1-Score", f"{ov.f1_score:.4f}", "Harmonic mean of Precision and Recall"])
            writer.writerow(["Accuracy", f"{ov.accuracy:.4f}", "(TP + TN) / Total"])
            writer.writerow(["Mean Detection Latency", f"{lat.mean_latency:.2f}", "Average steps to detect attack episode"])
            writer.writerow(["Median Detection Latency", f"{lat.median_latency:.2f}", "Median steps to detect attack episode"])
            writer.writerow(["P95 Detection Latency", f"{lat.p95_latency:.2f}", "95th percentile detection steps"])
            writer.writerow(["Episode Detection Rate", f"{lat.episode_detection_rate:.4f}", "Fraction of attack episodes detected"])

    def _export_per_class_csv(self, summary: EvaluationSummary, path: Path) -> None:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Attack Class",
                "Total Samples",
                "Detected Samples",
                "Detection Rate",
                "Precision",
                "Recall",
                "F1-Score",
                "Mean Latency (steps)",
                "Median Latency",
                "P95 Latency",
                "Episode Detection Rate",
            ])
            for atk_class, metrics in summary.per_class.items():
                writer.writerow([
                    atk_class,
                    metrics.total_samples,
                    metrics.detected_samples,
                    f"{metrics.detection_rate:.4f}",
                    f"{metrics.precision:.4f}",
                    f"{metrics.recall:.4f}",
                    f"{metrics.f1_score:.4f}",
                    f"{metrics.latency.mean_latency:.2f}",
                    f"{metrics.latency.median_latency:.2f}",
                    f"{metrics.latency.p95_latency:.2f}",
                    f"{metrics.latency.episode_detection_rate:.4f}",
                ])

    def _export_ablation_csv(self, summary: EvaluationSummary, path: Path) -> None:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Pipeline Configuration",
                "Detection Rate",
                "False Positive Rate",
                "False Negative Rate",
                "Precision",
                "Recall",
                "F1-Score",
                "Accuracy",
            ])
            for config_name, m in summary.ablation.items():
                writer.writerow([
                    config_name,
                    f"{m.detection_rate:.4f}",
                    f"{m.false_positive_rate:.4f}",
                    f"{m.false_negative_rate:.4f}",
                    f"{m.precision:.4f}",
                    f"{m.recall:.4f}",
                    f"{m.f1_score:.4f}",
                    f"{m.accuracy:.4f}",
                ])

    def _export_predictions_csv(self, detailed_predictions: List[Dict[str, Any]], path: Path) -> None:
        if not detailed_predictions:
            return
        keys = list(detailed_predictions[0].keys())
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(detailed_predictions)

    def _export_replay_limitations_doc(self, summary: EvaluationSummary, path: Path) -> None:
        replay_metrics = summary.per_class.get("replay_attack")
        det_rate_str = f"{replay_metrics.detection_rate * 100:.2f}%" if replay_metrics else "N/A"
        latency_str = f"{replay_metrics.latency.mean_latency:.2f} steps" if replay_metrics else "N/A"

        content = f"""# Empirical Analysis of Replay Attack Detection & Architectural Limitations

**Evaluation Split:** {summary.split_name}  
**Replay Detection Rate:** {det_rate_str}  
**Mean Replay Latency:** {latency_str}  

---

## 1. Executive Summary

Replay attacks represent a fundamental challenge for passive telemetry and semantic monitoring systems. In a replay attack, an adversary captures authentic, historically valid sensor telemetry and ledger records, and subsequently retransmits them into the monitoring stream.

Because individual replayed observations originally passed all physical and mathematical constraints, detecting them relies entirely on **temporal state continuity**, **sequence freshness**, and **environmental drift**.

---

## 2. When Replay Attacks Are Successfully Detected

The Optimus defender pipeline successfully detects replay attacks under the following conditions:

1. **Inventory Flow Desynchronization ($C_2$ Violation):**
   - If the warehouse has engaged in legitimate inbound or outbound shipment flows between the original recording and the replayed timestamp, replaying the old inventory count induces an instantaneous discrepancy against the ledger ($C_2$: $\\text{{inventory}}_t \\neq \\text{{inventory}}_{{t-1}} + \\text{{inbound}}_t - \\text{{outbound}}_t$).
2. **Environmental Discontinuity:**
   - Sudden discrete jumps in temperature or relative humidity between the current ambient state and the replayed snapshot trigger the **Temporal Engine** and **Isolation Forest ML** anomaly detector.
3. **Out-of-Order Sequence Counters:**
   - Transmitting duplicate or retrograde step numbers triggers the pipeline's **Sequence Freshness Check** (`SEQUENCE_ANOMALY`).

---

## 3. Structural Limitations & Undetected Replay Scenarios

Despite multi-stage defenses, replay attacks can successfully evade detection under specific operational boundaries:

1. **Static Warehouse Quiescence:**
   - If warehouse inventory is stationary (zero inbound, zero outbound) and the adversary updates the step counter monotonically, replaying an observation from 5 steps prior creates zero mathematical or physical invariant discrepancy.
2. **In-Envelope Environmental Drift:**
   - If the replayed sensor temperature and humidity fall within plausible short-term ambient drift tolerances (e.g. 4.2°C replayed as 4.3°C), the ML detector cannot statistically distinguish replay noise from true physical walk noise.
3. **Passive Ingestion Boundary:**
   - Passive application-layer monitors cannot independently verify sensor authenticity without cryptographic verification primitives.

---

## 4. Recommended Production Countermeasures

To achieve complete mitigation against replay attacks in production:

1. **Cryptographic Nonce / Challenge-Response:**
   - Require IoT gateway devices to sign observations with monotonic hardware nonces or asymmetric private keys.
2. **Authenticated Timestamps & TLS Integrity:**
   - Enforce synchronized Network Time Protocol (NTP) with strict drift rejection thresholds (< 500ms).
3. **HMAC Message Authentication Codes:**
   - Attach keyed HMAC digests over `(warehouse_id, step, timestamp, payload)` at the hardware sensor edge.
"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    def _generate_charts(self, summary: EvaluationSummary) -> Dict[str, str]:
        """Generate high-resolution PNG evaluation charts via Matplotlib."""
        import matplotlib
        matplotlib.use("Agg")  # Headless non-interactive backend
        import matplotlib.pyplot as plt

        chart_files = {}

        # 1. Confusion Matrix
        cm_path = self.output_dir / "confusion_matrix.png"
        ov = summary.overall
        fig, ax = plt.subplots(figsize=(6, 5))
        matrix = [[ov.tn, ov.fp], [ov.fn, ov.tp]]
        cax = ax.matshow(matrix, cmap="Blues")
        fig.colorbar(cax)

        for i in range(2):
            for j in range(2):
                val = matrix[i][j]
                color = "white" if val > (ov.total / 4) else "black"
                ax.text(j, i, f"{val:,}", ha="center", va="center", color=color, fontsize=14, fontweight="bold")

        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(["Predicted Normal", "Predicted Attack"], fontsize=11)
        ax.set_yticklabels(["Actual Normal", "Actual Attack"], fontsize=11)
        ax.set_title(f"Confusion Matrix ({summary.split_name.upper()} Split)", pad=20, fontsize=13, fontweight="bold")
        plt.tight_layout()
        plt.savefig(cm_path, dpi=200)
        plt.close()
        chart_files["confusion_matrix_chart"] = str(cm_path)

        # 2. Attack Class Performance Bar Chart
        class_chart_path = self.output_dir / "attack_class_performance.png"
        classes = list(summary.per_class.keys())
        det_rates = [summary.per_class[c].detection_rate * 100 for c in classes]
        f1_scores = [summary.per_class[c].f1_score * 100 for c in classes]

        x = range(len(classes))
        width = 0.35

        fig, ax = plt.subplots(figsize=(10, 5))
        rects1 = ax.bar([i - width/2 for i in x], det_rates, width, label="Detection Rate (%)", color="#1f77b4")
        rects2 = ax.bar([i + width/2 for i in x], f1_scores, width, label="F1-Score (%)", color="#2ca02c")

        ax.set_ylabel("Percentage (%)", fontsize=11)
        ax.set_title("Defender Performance by Attack Class", fontsize=13, fontweight="bold")
        ax.set_xticks(x)
        ax.set_xticklabels([c.replace("_", "\n") for c in classes], fontsize=9)
        ax.set_ylim(0, 110)
        ax.legend(loc="lower right")
        ax.grid(axis="y", linestyle="--", alpha=0.7)

        # Add values on top of bars
        for rect in rects1:
            h = rect.get_height()
            ax.annotate(f"{h:.1f}%", xy=(rect.get_x() + rect.get_width() / 2, h), xytext=(0, 3),
                        textcoords="offset points", ha="center", va="bottom", fontsize=8)
        for rect in rects2:
            h = rect.get_height()
            ax.annotate(f"{h:.1f}%", xy=(rect.get_x() + rect.get_width() / 2, h), xytext=(0, 3),
                        textcoords="offset points", ha="center", va="bottom", fontsize=8)

        plt.tight_layout()
        plt.savefig(class_chart_path, dpi=200)
        plt.close()
        chart_files["attack_class_chart"] = str(class_chart_path)

        # 3. Detection Latency Bar Chart
        lat_chart_path = self.output_dir / "detection_latency.png"
        mean_lats = [summary.per_class[c].latency.mean_latency for c in classes]
        p95_lats = [summary.per_class[c].latency.p95_latency for c in classes]

        fig, ax = plt.subplots(figsize=(10, 5))
        rects1 = ax.bar([i - width/2 for i in x], mean_lats, width, label="Mean Latency (steps)", color="#ff7f0e")
        rects2 = ax.bar([i + width/2 for i in x], p95_lats, width, label="P95 Latency (steps)", color="#d62728")

        ax.set_ylabel("Steps from Attack Onset to Alert", fontsize=11)
        ax.set_title("Detection Latency Across Attack Classes", fontsize=13, fontweight="bold")
        ax.set_xticks(x)
        ax.set_xticklabels([c.replace("_", "\n") for c in classes], fontsize=9)
        ax.legend(loc="upper right")
        ax.grid(axis="y", linestyle="--", alpha=0.7)

        for rect in rects1:
            h = rect.get_height()
            ax.annotate(f"{h:.1f}", xy=(rect.get_x() + rect.get_width() / 2, h), xytext=(0, 3),
                        textcoords="offset points", ha="center", va="bottom", fontsize=8)
        for rect in rects2:
            h = rect.get_height()
            ax.annotate(f"{h:.1f}", xy=(rect.get_x() + rect.get_width() / 2, h), xytext=(0, 3),
                        textcoords="offset points", ha="center", va="bottom", fontsize=8)

        plt.tight_layout()
        plt.savefig(lat_chart_path, dpi=200)
        plt.close()
        chart_files["detection_latency_chart"] = str(lat_chart_path)

        # 4. Pipeline Stage Ablation Chart
        ablation_chart_path = self.output_dir / "stage_ablation.png"
        stages = list(summary.ablation.keys())
        stage_det = [summary.ablation[s].detection_rate * 100 for s in stages]
        stage_fpr = [summary.ablation[s].false_positive_rate * 100 for s in stages]

        x_s = range(len(stages))
        fig, ax = plt.subplots(figsize=(12, 5))
        rects1 = ax.bar([i - width/2 for i in x_s], stage_det, width, label="Detection Rate (%)", color="#1f77b4")
        rects2 = ax.bar([i + width/2 for i in x_s], stage_fpr, width, label="False Positive Rate (%)", color="#d62728")

        ax.set_ylabel("Percentage (%)", fontsize=11)
        ax.set_title("Stage Ablation: Detection Rate vs False Positive Rate", fontsize=13, fontweight="bold")
        ax.set_xticks(x_s)
        ax.set_xticklabels([s.replace("_", "\n") for s in stages], fontsize=8)
        ax.set_ylim(0, 110)
        ax.legend(loc="upper left")
        ax.grid(axis="y", linestyle="--", alpha=0.7)

        for rect in rects1:
            h = rect.get_height()
            ax.annotate(f"{h:.1f}%", xy=(rect.get_x() + rect.get_width() / 2, h), xytext=(0, 3),
                        textcoords="offset points", ha="center", va="bottom", fontsize=8)
        for rect in rects2:
            h = rect.get_height()
            ax.annotate(f"{h:.1f}%", xy=(rect.get_x() + rect.get_width() / 2, h), xytext=(0, 3),
                        textcoords="offset points", ha="center", va="bottom", fontsize=8)

        plt.tight_layout()
        plt.savefig(ablation_chart_path, dpi=200)
        plt.close()
        chart_files["stage_ablation_chart"] = str(ablation_chart_path)

        return chart_files
