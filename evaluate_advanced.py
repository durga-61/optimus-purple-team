#!/usr/bin/env python3
"""Run the advanced OPTIMUS experiments and export reproducible artifacts."""

import argparse
import logging
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.evaluation.advanced_experiments import run_all_experiments


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output-dir", default="evaluation_results")
    parser.add_argument("--num-normal", type=int, default=12000)
    parser.add_argument("--num-attack-per-class", type=int, default=2000)
    parser.add_argument("--episodes-per-class", type=int, default=8)
    parser.add_argument("--episode-length", type=int, default=8)
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Small dataset/frontier for a quick end-to-end smoke run.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    if args.fast:
        args.num_normal = 1200
        args.num_attack_per_class = 200
        args.episodes_per_class = 2
        args.episode_length = 4
    run_all_experiments(
        seed=args.seed,
        num_normal=args.num_normal,
        num_attack_per_class=args.num_attack_per_class,
        output_dir=args.output_dir,
        episodes_per_class=args.episodes_per_class,
        episode_length=args.episode_length,
    )
