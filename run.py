"""Entry point script for the Organization Information Security Platform.

Runs a standalone demonstration of the ColdStorageWarehouse simulator feeding the
complete Phase 3 DefenderService security analysis pipeline.
"""

import argparse
import logging
import sys
import time

from app.config import settings
from app.defender.service import DefenderService
from app.simulator.scenarios import inject_capacity_manipulation
from app.simulator.warehouse import ColdStorageWarehouse

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("platform.runner")


def print_analysis_box(title: str, res) -> None:
    """Pretty-print security analysis pipeline stage outputs."""
    print("=" * 72)
    print(f" {title.upper()}")
    print("=" * 72)
    print(f"Observation State:")
    print(
        f"  Warehouse: {res.observation.warehouse} | Step: {res.observation.step} | "
        f"Capacity: {res.observation.capacity:.1f}t | Inventory: {res.observation.inventory:.1f}t | "
        f"Free Capacity: {res.observation.free_capacity:.1f}t"
    )
    print(
        f"  Temperature: {res.observation.temperature:.1f} °C | Humidity: {res.observation.humidity:.1f}% | "
        f"Inbound: {res.observation.inbound:.1f}t | Outbound: {res.observation.outbound:.1f}t"
    )
    print("-" * 72)
    print("PIPELINE STAGE EVALUATIONS (Actual Computed Backend Results):")
    print(f"  1. ML Detection:        {res.ml.status:<12} (Anomaly Score: {res.ml.anomaly_score:.3f})")
    print(f"  2. Semantic Integrity:  {res.semantic.status:<12} (Score: {res.semantic.semantic_score:.2f}, Violated: {res.semantic.violated_constraints})")
    for c in res.semantic.constraints:
        print(f"     * [{c.status:<8}] {c.name}: {c.message}")
    print(f"  3. Temporal Analysis:   {res.temporal.status:<12} (Score: {res.temporal.temporal_score:.2f}, Persistence: {res.temporal.persistence}, Recurrence: {res.temporal.recurrence})")
    print(f"  4. Structural Graph:    {res.structural.status:<12} (Score: {res.structural.structural_score:.2f}, Affected: {res.structural.affected_nodes})")
    print("-" * 72)
    print("JOINT SECURITY DECISION:")
    print(f"  Classification:         {res.decision.classification}")
    print(f"  Risk Score:             {res.decision.risk_score:.3f}")
    print(f"  Integrity Score:        {res.decision.integrity_score:.1f}%")
    print(f"  Active Alerts:          {len(res.alerts)}")
    print(f"  Explanation:            {res.decision.explanation}")
    print("=" * 72 + "\n")


def run_defender_demo(steps: int = 5, seed: int = 42) -> None:
    """Demonstrate the defender pipeline processing normal observations and attack injection."""
    logger.info("Initializing DefenderService and ColdStorageWarehouse...")
    warehouse = ColdStorageWarehouse(seed=seed)
    service = DefenderService()

    # 1. Process normal baseline observations
    logger.info(f"Processing {steps} normal operational steps through Defender pipeline...")
    last_normal_res = None
    for _ in range(steps):
        obs = warehouse.step()
        last_normal_res = service.analyze(obs)

    # Display Normal Observation pipeline execution
    print_analysis_box("Scene 1 & 2: Normal Operating Observation", last_normal_res)

    # 2. Trigger Capacity Manipulation Attack (Demo Scenario Section 22)
    logger.info("Injecting demonstration attack: Capacity Manipulation (Free capacity 8 -> 40)...")
    curr_obs = warehouse.step(inbound=1.0, outbound=0.5)
    attacked_obs = inject_capacity_manipulation(curr_obs, reported_free_capacity=40.0)

    # Run through the identical defender pipeline
    attack_res = service.analyze(attacked_obs)

    # Display Attacked Observation pipeline execution
    print_analysis_box("Scene 3 & 4: Capacity Manipulation Attack Detected", attack_res)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Information Security Platform")
    parser.add_argument("--demo", action="store_true", help="Run standalone terminal demonstration instead of HTTP API server")
    parser.add_argument("--host", type=str, default=settings.HOST, help="Host interface to bind server")
    parser.add_argument("--port", type=int, default=settings.PORT, help="Port to bind server")
    parser.add_argument("--steps", type=int, default=5, help="Number of baseline normal steps (for --demo)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    args = parser.parse_args()

    if args.demo:
        run_defender_demo(steps=args.steps, seed=args.seed)
    else:
        import uvicorn
        logger.info(f"Starting FastAPI server on http://{args.host}:{args.port}")
        logger.info(f"Swagger API Docs: http://{args.host}:{args.port}/api/docs")
        uvicorn.run("app.api.main:app", host=args.host, port=args.port, reload=settings.DEBUG)


if __name__ == "__main__":
    main()
