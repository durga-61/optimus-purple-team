"""Semantic integrity engine for cold-storage warehouse operational records.

Verifies physical and operational invariants across inventory, capacity, flow, and
environmental bounds (C1, C2, and C3 constraints).
"""

import logging
from typing import List, Optional, Tuple
import numpy as np

from app.config import settings
from app.defender.models import ConstraintResult, SemanticResult
from app.simulator.models import WarehouseObservation

logger = logging.getLogger("defender.semantic")


class SemanticEngine:
    """Evaluates semantic integrity constraints on cold-storage warehouse observations."""

    def __init__(
        self,
        c1_tolerance: float = settings.C1_CAPACITY_TOLERANCE,
        c2_tolerance: float = settings.C2_FLOW_TOLERANCE,
        c3_temp_range: Tuple[float, float] = settings.C3_HISTORICAL_TEMP_RANGE,
        c3_humidity_range: Tuple[float, float] = settings.C3_HISTORICAL_HUMIDITY_RANGE,
    ):
        self.c1_tolerance = c1_tolerance
        self.c2_tolerance = c2_tolerance
        self.c3_temp_range = c3_temp_range
        self.c3_humidity_range = c3_humidity_range

    def check_c1_capacity(self, obs: WarehouseObservation) -> ConstraintResult:
        """C1: Capacity Consistency Check.
        
        Asserts that reported inventory + free capacity approximately equals total capacity.
        inventory + free_capacity ≈ total_capacity
        """
        calculated_total = round(obs.inventory + obs.free_capacity, 2)
        diff = round(abs(calculated_total - obs.capacity), 2)

        if diff > self.c1_tolerance:
            direction = ">" if calculated_total > obs.capacity else "<"
            msg = (
                f"C1 Capacity violation: inventory ({obs.inventory:.1f}t) + "
                f"free capacity ({obs.free_capacity:.1f}t) = {calculated_total:.1f}t {direction} "
                f"total capacity ({obs.capacity:.1f}t). Discrepancy: {diff:.2f}t "
                f"(tolerance: {self.c1_tolerance:.2f}t)."
            )
            status = "VIOLATED"
        else:
            msg = (
                f"C1 Capacity consistent: inventory ({obs.inventory:.1f}t) + "
                f"free capacity ({obs.free_capacity:.1f}t) ≈ total capacity ({obs.capacity:.1f}t)."
            )
            status = "PASSED"

        return ConstraintResult(
            constraint="C1",
            name="Capacity Consistency",
            status=status,
            expected=obs.capacity,
            actual=calculated_total,
            difference=diff,
            tolerance=self.c1_tolerance,
            message=msg,
        )

    def check_c2_inventory_flow(
        self,
        current_obs: WarehouseObservation,
        previous_obs: Optional[WarehouseObservation],
    ) -> ConstraintResult:
        """C2: Inventory Flow Consistency Check.
        
        Asserts current inventory equals previous inventory + inbound - outbound within tolerance.
        current_inventory ≈ previous_inventory + inbound - outbound
        """
        if previous_obs is None:
            return ConstraintResult(
                constraint="C2",
                name="Inventory Flow Consistency",
                status="PASSED",
                expected=current_obs.inventory,
                actual=current_obs.inventory,
                difference=0.0,
                tolerance=self.c2_tolerance,
                message="C2 Flow check passed: Baseline step, no prior state to compare.",
            )

        expected_inventory = round(
            previous_obs.inventory + current_obs.inbound - current_obs.outbound,
            2,
        )
        diff = round(abs(current_obs.inventory - expected_inventory), 2)

        if diff > self.c2_tolerance:
            msg = (
                f"C2 Flow violation: current inventory ({current_obs.inventory:.1f}t) does not match "
                f"expected ({expected_inventory:.1f}t) computed from previous ({previous_obs.inventory:.1f}t) + "
                f"inbound ({current_obs.inbound:.1f}t) - outbound ({current_obs.outbound:.1f}t). "
                f"Discrepancy: {diff:.2f}t (tolerance: {self.c2_tolerance:.2f}t)."
            )
            status = "VIOLATED"
        else:
            msg = (
                f"C2 Flow consistent: inventory movement matches shipment ledger "
                f"within {self.c2_tolerance:.2f}t tolerance."
            )
            status = "PASSED"

        return ConstraintResult(
            constraint="C2",
            name="Inventory Flow Consistency",
            status=status,
            expected=expected_inventory,
            actual=current_obs.inventory,
            difference=diff,
            tolerance=self.c2_tolerance,
            message=msg,
        )

    def check_c3_historical(
        self,
        current_obs: WarehouseObservation,
        history: Optional[List[WarehouseObservation]] = None,
    ) -> ConstraintResult:
        """C3: Historical Operating Envelope Consistency Check.
        
        Compares temperature and humidity to normal cold-storage bounds and recent history.
        Does not treat deviation as automatic proof of an attack, but as supporting evidence.
        """
        min_temp, max_temp = self.c3_temp_range
        min_hum, max_hum = self.c3_humidity_range

        violations = []
        if current_obs.temperature < min_temp or current_obs.temperature > max_temp:
            violations.append(
                f"temperature {current_obs.temperature:.1f}°C outside safe operating range [{min_temp:.1f}, {max_temp:.1f}]°C"
            )
        if current_obs.humidity < min_hum or current_obs.humidity > max_hum:
            violations.append(
                f"humidity {current_obs.humidity:.1f}% outside safe operating range [{min_hum:.1f}, {max_hum:.1f}]%"
            )

        # Statistical check if sufficient history exists (> 5 observations)
        if history and len(history) >= 5:
            past_temps = [h.temperature for h in history]
            mean_temp = float(np.mean(past_temps))
            std_temp = max(0.2, float(np.std(past_temps)))
            z_temp = abs(current_obs.temperature - mean_temp) / std_temp
            if z_temp > 4.0 and not violations:
                violations.append(f"temperature sudden spike (Z-score: {z_temp:.1f})")

        if violations:
            status = "WARNING"
            diff = 1.0
            msg = f"C3 Historical operating deviation detected: {'; '.join(violations)}."
        else:
            status = "PASSED"
            diff = 0.0
            msg = (
                f"C3 Operating conditions within normal bounds: "
                f"Temp={current_obs.temperature:.1f}°C (envelope {min_temp}-{max_temp}°C), "
                f"Humidity={current_obs.humidity:.1f}% (envelope {min_hum}-{max_hum}%)."
            )

        return ConstraintResult(
            constraint="C3",
            name="Historical Consistency",
            status=status,
            expected={"temperature_range": list(self.c3_temp_range), "humidity_range": list(self.c3_humidity_range)},
            actual={"temperature": current_obs.temperature, "humidity": current_obs.humidity},
            difference=diff,
            tolerance=0.0,
            message=msg,
        )

    def analyze(
        self,
        current_obs: WarehouseObservation,
        previous_obs: Optional[WarehouseObservation] = None,
        history: Optional[List[WarehouseObservation]] = None,
    ) -> SemanticResult:
        """Run all semantic constraint checks and return an aggregated SemanticResult."""
        c1 = self.check_c1_capacity(current_obs)
        c2 = self.check_c2_inventory_flow(current_obs, previous_obs)
        c3 = self.check_c3_historical(current_obs, history)

        constraints = [c1, c2, c3]
        violated = [c.constraint for c in constraints if c.status == "VIOLATED"]
        warnings = [c.constraint for c in constraints if c.status == "WARNING"]

        # Calculate semantic score in [0.0, 1.0]
        # C1 and C2 are hard operational integrity constraints
        # C3 is a supporting environmental warning
        score = 0.0
        if "C1" in violated:
            score += 0.50
        if "C2" in violated:
            score += 0.40
        if "C3" in warnings or "C3" in violated:
            score += 0.15

        semantic_score = round(min(1.0, score), 2)

        if violated:
            status = "VIOLATION"
            explanation = (
                f"Semantic integrity violations detected ({', '.join(violated)}): "
                f"{'; '.join([c.message for c in constraints if c.status == 'VIOLATED'])}"
            )
        elif warnings:
            status = "WARNING"
            explanation = f"Semantic warning: {c3.message}"
        else:
            status = "NORMAL"
            explanation = "All operational and physical semantic constraints satisfied."

        evidence = {
            "inventory": current_obs.inventory,
            "free_capacity": current_obs.free_capacity,
            "capacity": current_obs.capacity,
            "inbound": current_obs.inbound,
            "outbound": current_obs.outbound,
            "c1_difference": c1.difference,
            "c2_difference": c2.difference,
        }

        return SemanticResult(
            semantic_score=semantic_score,
            status=status,
            constraints=constraints,
            violated_constraints=violated,
            evidence=evidence,
            explanation=explanation,
        )
