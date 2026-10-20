"""Deterministic Attack Matrix and Recovery Validation Suite.

Executes each deterministic scenario through the live DefenderService pipeline,
measuring exact pipeline outputs, alert triggers, and temporal decay recovery.
"""

import json
import os
import sys
import pytest

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.defender.service import DefenderService
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


def evaluate_scenario(service: DefenderService, obs: WarehouseObservation):
    """Run an observation through the pipeline and extract formatted summary fields."""
    res = service.analyze(obs)

    c1 = next((c for c in res.semantic.constraints if c.constraint == "C1"), None)
    c2 = next((c for c in res.semantic.constraints if c.constraint == "C2"), None)
    c3 = next((c for c in res.semantic.constraints if c.constraint == "C3"), None)

    return {
        "scenario": obs.attack_type or "Normal Operation",
        "step": res.step,
        "ml": {
            "classification": res.ml.status,
            "anomaly_score": round(res.ml.anomaly_score, 3),
            "is_anomaly": res.ml.is_anomaly,
        },
        "c1": {
            "status": c1.status if c1 else "N/A",
            "difference": c1.difference if c1 else 0.0,
            "message": c1.message if c1 else "",
        },
        "c2": {
            "status": c2.status if c2 else "N/A",
            "difference": c2.difference if c2 else 0.0,
            "message": c2.message if c2 else "",
        },
        "c3": {
            "status": c3.status if c3 else "N/A",
            "difference": c3.difference if c3 else 0.0,
            "message": c3.message if c3 else "",
        },
        "temporal": {
            "status": res.temporal.status,
            "score": round(res.temporal.temporal_score, 3),
            "persistence": res.temporal.persistence,
            "recurrence": res.temporal.recurrence,
        },
        "structural": {
            "status": res.structural.status,
            "score": round(res.structural.structural_score, 3),
            "affected_nodes": res.structural.affected_nodes,
        },
        "final": {
            "classification": res.decision.classification,
            "risk_score": round(res.decision.risk_score, 3),
            "integrity_score": round(res.decision.integrity_score, 1),
            "alert_generated": len(res.alerts) > 0,
            "explanation": res.decision.explanation,
        },
    }


class TestDeterministicAttackMatrix:
    """Automated test cases executing each matrix scenario."""

    def test_matrix_and_recovery_execution(self):
        service = DefenderService()
        wh = ColdStorageWarehouse(seed=42)

        # Baseline setup
        service.analyze(wh.get_current_observation())

        # 1. Normal Operation
        normal_obs = wh.step()
        res_normal = evaluate_scenario(service, normal_obs)
        assert res_normal["final"]["classification"] == "NORMAL"
        assert res_normal["final"]["alert_generated"] is False
        assert res_normal["c1"]["status"] == "PASSED"
        assert res_normal["c2"]["status"] == "PASSED"
        assert res_normal["c3"]["status"] == "PASSED"

        # 2. Capacity Manipulation
        cap_obs = inject_capacity_manipulation(wh.step(), reported_free_capacity=40.0)
        res_cap = evaluate_scenario(service, cap_obs)
        assert res_cap["c1"]["status"] == "VIOLATED"
        assert res_cap["final"]["classification"] == "POTENTIAL_ATTACK"
        assert res_cap["final"]["alert_generated"] is True

        # Recovery from Capacity attack
        for _ in range(5):
            rec_obs = wh.step()
            service.analyze(rec_obs)
        assert service.get_latest_analysis().decision.classification == "NORMAL"

        # 3. Inventory Manipulation
        inv_obs = inject_inventory_manipulation(wh.step(), manipulated_inventory=22.0)
        res_inv = evaluate_scenario(service, inv_obs)
        assert res_inv["c2"]["status"] == "VIOLATED"
        assert res_inv["final"]["classification"] == "POTENTIAL_ATTACK"
        assert res_inv["final"]["alert_generated"] is True

        # Recovery from Inventory attack (clear 10-step window so recurrence decays to 0)
        for _ in range(10):
            service.analyze(wh.step())
        assert service.get_latest_analysis().decision.classification == "NORMAL"

        # 4. Sensor Spoofing
        sensor_obs = inject_sensor_spoofing(wh.step(), spoofed_temperature=28.0, spoofed_humidity=95.0)
        res_sensor = evaluate_scenario(service, sensor_obs)
        assert res_sensor["c3"]["status"] == "WARNING"
        assert res_sensor["final"]["classification"] in ("SUSPICIOUS", "LOW")

        # Recovery
        for _ in range(5):
            service.analyze(wh.step())

        # 5. Replay Attack
        past_obs = wh.history[0]  # Old historical observation
        curr_obs = wh.step(inbound=2.0, outbound=0.0)
        replay_obs = inject_replay_attack(current_obs=curr_obs, previous_obs=past_obs)
        res_replay = evaluate_scenario(service, replay_obs)
        # In an evolving system, unrecorded inventory leap breaks C2 flow conservation
        assert res_replay["c2"]["status"] == "VIOLATED"
        assert res_replay["final"]["classification"] == "POTENTIAL_ATTACK"

        # Recovery
        for _ in range(5):
            service.analyze(wh.step())

        # 6. Coordinated Weak Manipulation
        coord_obs = inject_coordinated_manipulation(wh.step(), inventory_delta=-2.0, reported_free_capacity_delta=1.0)
        res_coord = evaluate_scenario(service, coord_obs)
        # Capacity discrepancy = abs((inv-2) + (free+1) - 50) = 1.0 > tolerance 0.5
        assert res_coord["c1"]["status"] == "VIOLATED"
        assert res_coord["final"]["classification"] == "POTENTIAL_ATTACK"

        # Recovery
        for _ in range(5):
            service.analyze(wh.step())

        # 7. Multi-Source Manipulation
        multi_obs = inject_multi_source_manipulation(wh.step())
        res_multi = evaluate_scenario(service, multi_obs)
        assert res_multi["structural"]["status"] == "MULTI_SOURCE"
        assert res_multi["c2"]["status"] == "VIOLATED"


def run_full_matrix_report():
    """Standalone runner that prints out the exact structured results for all 7 scenarios and recovery."""
    service = DefenderService()
    wh = ColdStorageWarehouse(seed=42)

    # Prime baseline
    service.analyze(wh.get_current_observation())

    print("\n" + "=" * 80)
    print(" DETERMINISTIC ATTACK-MATRIX VALIDATION REPORT")
    print("=" * 80)

    # 1. Normal Operation
    obs1 = wh.step()
    res1 = evaluate_scenario(service, obs1)

    # 2. Capacity Manipulation
    obs2 = inject_capacity_manipulation(wh.step(), reported_free_capacity=40.0)
    res2 = evaluate_scenario(service, obs2)

    # Recovery 1 (observe decay over 4 steps)
    recovery_cap = []
    for _ in range(4):
        rec_obs = wh.step()
        recovery_cap.append(evaluate_scenario(service, rec_obs))

    # 3. Inventory Manipulation
    obs3 = inject_inventory_manipulation(wh.step(), manipulated_inventory=20.0)
    res3 = evaluate_scenario(service, obs3)

    for _ in range(4):
        service.analyze(wh.step())

    # 4. Sensor Spoofing
    obs4 = inject_sensor_spoofing(wh.step(), spoofed_temperature=28.0, spoofed_humidity=95.0)
    res4 = evaluate_scenario(service, obs4)

    for _ in range(4):
        service.analyze(wh.step())

    # 5. Replay Attack
    past_obs = wh.history[0]
    curr_step = wh.step(inbound=2.0, outbound=0.0)
    obs5 = inject_replay_attack(current_obs=curr_step, previous_obs=past_obs)
    res5 = evaluate_scenario(service, obs5)

    for _ in range(4):
        service.analyze(wh.step())

    # 6. Coordinated Weak Manipulation
    obs6 = inject_coordinated_manipulation(wh.step(), inventory_delta=-2.0, reported_free_capacity_delta=1.0)
    res6 = evaluate_scenario(service, obs6)

    for _ in range(4):
        service.analyze(wh.step())

    # 7. Multi-Source Manipulation
    obs7 = inject_multi_source_manipulation(wh.step())
    res7 = evaluate_scenario(service, obs7)

    scenarios = [res1, res2, res3, res4, res5, res6, res7]
    for idx, sc in enumerate(scenarios, 1):
        print(f"\n[{idx}] SCENARIO: {sc['scenario'].upper()}")
        print(f"  * ML Result:         {sc['ml']['classification']:<12} (Score: {sc['ml']['anomaly_score']}, Anomaly Flag: {sc['ml']['is_anomaly']})")
        print(f"  * C1 (Capacity):     {sc['c1']['status']:<12} (Diff: {sc['c1']['difference']}t, Msg: {sc['c1']['message']})")
        print(f"  * C2 (Flow):         {sc['c2']['status']:<12} (Diff: {sc['c2']['difference']}t, Msg: {sc['c2']['message']})")
        print(f"  * C3 (Historical):   {sc['c3']['status']:<12} (Diff: {sc['c3']['difference']}, Msg: {sc['c3']['message']})")
        print(f"  * Temporal Analysis: {sc['temporal']['status']:<12} (Score: {sc['temporal']['score']}, Persistence: {sc['temporal']['persistence']}, Recurrence: {sc['temporal']['recurrence']})")
        print(f"  * Structural Graph:  {sc['structural']['status']:<12} (Score: {sc['structural']['score']}, Affected: {sc['structural']['affected_nodes']})")
        print(f"  * Final Decision:    {sc['final']['classification']}")
        print(f"  * Final Risk Score:  {sc['final']['risk_score']} (Integrity: {sc['final']['integrity_score']}%)")
        print(f"  * Alert Generated:   {sc['final']['alert_generated']}")
        print(f"  * Explanation:       {sc['final']['explanation']}")

    print("\n" + "=" * 80)
    print(" RECOVERY / TEMPORAL-DECAY DEMONSTRATION (Post-Capacity Attack)")
    print("=" * 80)
    print(f"{'Step':<6} {'Temporal Status':<18} {'Temporal Score':<16} {'Persistence':<14} {'Classification':<18} {'Integrity Score':<16}")
    print("-" * 88)
    for r in recovery_cap:
        print(
            f"{r['step']:<6} "
            f"{r['temporal']['status']:<18} "
            f"{r['temporal']['score']:<16} "
            f"{r['temporal']['persistence']:<14} "
            f"{r['final']['classification']:<18} "
            f"{r['final']['integrity_score']:<16.1f}%"
        )
    print("=" * 80 + "\n")


if __name__ == "__main__":
    run_full_matrix_report()
