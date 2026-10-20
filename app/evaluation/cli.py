"""Repeatable Evaluation CLI for Industrial Cybersecurity Monitoring Platform."""

import argparse
import logging
import sys
from typing import Optional

from app.evaluation.dataset import (
    create_temporal_splits,
    generate_attack_dataset,
    generate_normal_dataset,
)
from app.evaluation.evaluator import EvaluationEngine
from app.evaluation.exporter import BenchmarkExporter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("evaluation.cli")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Repeatable Benchmark Evaluation CLI for Optimus Defender Pipeline.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--split",
        choices=["train", "val", "test", "all"],
        default="test",
        help="Dataset split to evaluate.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Deterministic random seed for generation and evaluation.",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="evaluation_results",
        help="Directory where CSVs, charts, and limitation reports will be saved.",
    )
    parser.add_argument(
        "--no-charts",
        action="store_true",
        help="Disable Matplotlib PNG chart generation.",
    )
    parser.add_argument(
        "--num-normal",
        type=int,
        default=12000,
        help="Number of normal warehouse observations to generate.",
    )
    parser.add_argument(
        "--num-attack-per-class",
        type=int,
        default=2000,
        help="Number of attack observations to generate per attack class (6 classes total).",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Quick execution mode: generates 1,200 normal and 200 attack per class for rapid testing.",
    )
    return parser


def format_table(headers: list[str], rows: list[list[str]]) -> str:
    """Render a clean, aligned ASCII table."""
    col_widths = [len(h) for h in headers]
    for row in rows:
        for idx, val in enumerate(row):
            col_widths[idx] = max(col_widths[idx], len(str(val)))

    sep = "+-" + "-+-".join("-" * w for w in col_widths) + "-+"
    header_str = "| " + " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers)) + " |"

    lines = [sep, header_str, sep]
    for row in rows:
        row_str = "| " + " | ".join(str(val).ljust(col_widths[i]) for i, val in enumerate(row)) + " |"
        lines.append(row_str)
    lines.append(sep)
    return "\n".join(lines)


def run_evaluation(args: Optional[argparse.Namespace] = None) -> int:
    if args is None:
        parser = build_parser()
        args = parser.parse_args()

    num_normal = 1200 if args.fast else args.num_normal
    num_atk = 200 if args.fast else args.num_attack_per_class

    print("=" * 80)
    print(" OPTIMUS DEFENDER PIPELINE — DATASET & BENCHMARK EVALUATION HARNESS")
    print("=" * 80)
    print(f" Split Selection:         {args.split.upper()}")
    print(f" Random Seed:             {args.seed}")
    print(f" Output Directory:        {args.output_dir}")
    print(f" Normal Observations:     {num_normal:,}")
    print(f" Attack Observations:     {num_atk * 6:,} ({num_atk:,} per class x 6 classes)")
    print(f" Total Evaluation Volume: {num_normal + (num_atk * 6):,} samples")
    print(f" Chart Generation:        {'Disabled' if args.no_charts else 'Enabled'}")
    print("-" * 80)

    # 1. Deterministic Dataset Generation
    print("\n[1/4] Generating verified normal observations (strict C1, C2, C3 verification)...")
    normal_records = generate_normal_dataset(num_samples=num_normal, seed=args.seed)

    print("[2/4] Generating structured attack observations across 6 attack classes...")
    attack_records = generate_attack_dataset(num_samples_per_class=num_atk, seed=args.seed)

    # 2. Temporal Splitting
    print("[3/4] Partitioning into reproducible chronological train/val/test splits...")
    splits = create_temporal_splits(
        normal_records=normal_records,
        attack_records=attack_records,
        train_ratio=0.60,
        val_ratio=0.20,
        test_ratio=0.20,
    )

    # Select split records to evaluate
    if args.split == "train":
        eval_records = splits.train
    elif args.split == "val":
        eval_records = splits.val
    elif args.split == "all":
        eval_records = normal_records + attack_records
    else:  # "test"
        eval_records = splits.test

    # 3. Execution through Defender Pipeline
    print(f"[4/4] Fitting ML baseline on training normal records and evaluating {len(eval_records):,} samples...")
    engine = EvaluationEngine(training_records=splits.train, random_state=args.seed)
    summary, detailed_predictions = engine.evaluate_split(records=eval_records, split_name=args.split)

    # 4. Display Results
    ov = summary.overall
    lat = summary.latency

    print("\n" + "=" * 80)
    print(f" BENCHMARK EVALUATION RESULTS ({args.split.upper()} SPLIT)")
    print("=" * 80)

    summary_rows = [
        ["Total Evaluated Samples", f"{ov.total:,}"],
        ["True Positives (TP)", f"{ov.tp:,}"],
        ["False Positives (FP)", f"{ov.fp:,}"],
        ["True Negatives (TN)", f"{ov.tn:,}"],
        ["False Negatives (FN)", f"{ov.fn:,}"],
        ["Detection Rate (Recall)", f"{ov.detection_rate * 100:.2f}%"],
        ["False Positive Rate (FPR)", f"{ov.false_positive_rate * 100:.2f}%"],
        ["False Negative Rate (FNR)", f"{ov.false_negative_rate * 100:.2f}%"],
        ["Precision", f"{ov.precision * 100:.2f}%"],
        ["F1-Score", f"{ov.f1_score * 100:.2f}%"],
        ["Overall Accuracy", f"{ov.accuracy * 100:.2f}%"],
        ["Mean Detection Latency", f"{lat.mean_latency:.2f} steps"],
        ["Median Detection Latency", f"{lat.median_latency:.2f} steps"],
        ["P95 Detection Latency", f"{lat.p95_latency:.2f} steps"],
        ["Episode Detection Rate", f"{lat.episode_detection_rate * 100:.2f}% ({lat.detected_episodes}/{lat.total_episodes} episodes)"],
    ]
    print(format_table(["Benchmark Metric", "Score / Value"], summary_rows))

    # Per-Class Table
    print("\nPER-ATTACK-CLASS BREAKDOWN:")
    class_headers = ["Attack Class", "Total", "Detected", "Det Rate", "Precision", "F1", "Mean Latency", "P95 Lat"]
    class_rows = []
    for atk_name, m in summary.per_class.items():
        class_rows.append([
            atk_name,
            f"{m.total_samples:,}",
            f"{m.detected_samples:,}",
            f"{m.detection_rate * 100:.2f}%",
            f"{m.precision * 100:.2f}%",
            f"{m.f1_score * 100:.2f}%",
            f"{m.latency.mean_latency:.2f} steps",
            f"{m.latency.p95_latency:.2f} steps",
        ])
    print(format_table(class_headers, class_rows))

    # Stage Ablation Table
    print("\nSTAGE ABLATION COMPARISON:")
    abl_headers = ["Configuration", "Detection Rate", "FPR", "Precision", "Recall", "F1-Score"]
    abl_rows = []
    for stage_name, sm in summary.ablation.items():
        abl_rows.append([
            stage_name,
            f"{sm.detection_rate * 100:.2f}%",
            f"{sm.false_positive_rate * 100:.2f}%",
            f"{sm.precision * 100:.2f}%",
            f"{sm.recall * 100:.2f}%",
            f"{sm.f1_score * 100:.2f}%",
        ])
    print(format_table(abl_headers, abl_rows))

    # 5. Export Artifacts
    print(f"\nExporting benchmark artifacts to directory: {args.output_dir}/")
    exporter = BenchmarkExporter(output_dir=args.output_dir)
    exported = exporter.export_all(
        summary=summary,
        detailed_predictions=detailed_predictions,
        generate_charts=not args.no_charts,
    )

    for name, path in exported.items():
        print(f"  [+] {name}: {path}")

    print("\nBenchmark evaluation completed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(run_evaluation())
