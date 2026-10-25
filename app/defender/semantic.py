"""Semantic integrity engine for cold-storage warehouse operational records.

Verifies physical and operational invariants across inventory, capacity, flow,
environmental bounds, and multi-sensor spatial consistency (C1, C2, C3, and C4 constraints).
Handles real recorded datasets by explicitly marking ledger invariants as NOT_APPLICABLE
rather than fabricating data.
"""

import logging
from typing import Any, List, Optional, Tuple
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
        spatial_delta_temp_max: float = settings.ENVIRONMENTAL_DELTA_T_MAX,
    ):
        self.c1_tolerance = c1_tolerance
        self.c2_tolerance = c2_tolerance
        self.c3_temp_range = c3_temp_range
        self.c3_humidity_range = c3_humidity_range
        self.spatial_delta_temp_max = spatial_delta_temp_max
        self.custom_invariants: List[Any] = []

    def add_invariant(self, invariant: object) -> None:
        """Install a validated mined invariant (must expose ``check(obs, prev)``)."""
        if not hasattr(invariant, "check"):
            raise TypeError("Custom invariants must expose a check(obs, previous) method")
        candidate_id = getattr(invariant, "candidate_id", None)
        if candidate_id and any(
            getattr(existing, "candidate_id", None) == candidate_id
            for existing in self.custom_invariants
        ):
            raise ValueError(f"Invariant '{candidate_id}' is already active")
        self.custom_invariants.append(invariant)

    def clear_invariants(self) -> None:
        """Remove all mined invariants, restoring baseline C1/C2/C3 behavior."""
        self.custom_invariants.clear()

    def check_c1_capacity(self, obs: WarehouseObservation) -> ConstraintResult:
        """C1: Capacity Consistency Check.
        
        Asserts that reported inventory + free capacity approximately equals total capacity:
        inventory + free_capacity ≈ total_capacity.
        Returns NOT_APPLICABLE if ledger measurements are unavailable in the source data.
        """
        if obs.capacity is None or obs.inventory is None or obs.free_capacity is None:
            return ConstraintResult(
                constraint="C1",
                name="Capacity Consistency",
                status="NOT_APPLICABLE",
                expected=0.0,
                actual=0.0,
                difference=0.0,
                tolerance=self.c1_tolerance,
                message="C1 Capacity Consistency not applicable: capacity and inventory ledger fields not present in environmental dataset.",
            )

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
        
        Asserts current inventory equals previous inventory + inbound - outbound within tolerance:
        current_inventory ≈ previous_inventory + inbound - outbound.
        Returns NOT_APPLICABLE if ledger flow measurements are unavailable in the source data.
        """
        if (
            current_obs.inventory is None
            or current_obs.inbound is None
            or current_obs.outbound is None
            or (previous_obs is not None and previous_obs.inventory is None)
        ):
            return ConstraintResult(
                constraint="C2",
                name="Inventory Flow Consistency",
                status="NOT_APPLICABLE",
                expected=0.0,
                actual=0.0,
                difference=0.0,
                tolerance=self.c2_tolerance,
                message="C2 Inventory Flow not applicable: inventory and shipment ledger fields not present in environmental dataset.",
            )

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
        
        Compares temperature and humidity to documented cold-storage bounds and recent history.
        Distinguishes documented physical events (e.g. door openings) from unexplained anomalies.
        """
        if getattr(current_obs, "source", None) == "hohenheim":
            # Documented operating limits for University of Hohenheim Cold-Storage facility (mean 11.3°C, 5-16°C)
            min_temp, max_temp = (4.0, 16.0)
            min_hum, max_hum = (50.0, 95.0)
            # Pre-experiment sensor setup transient (before 'Begin' step 115)
            if current_obs.step < 120:
                max_temp = 25.0
        else:
            min_temp, max_temp = self.c3_temp_range
            min_hum, max_hum = self.c3_humidity_range

        violations = []
        is_door_action = (
            current_obs.active_action == "Door opened"
            or (history and any(getattr(h, "active_action", None) == "Door opened" for h in history[-3:]))
        )

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
            past_temps = [h.temperature for h in history if h.temperature is not None]
            if past_temps:
                mean_temp = float(np.mean(past_temps))
                std_temp = max(0.2, float(np.std(past_temps)))
                z_temp = abs(current_obs.temperature - mean_temp) / std_temp
                if z_temp > 4.0 and not violations:
                    violations.append(f"temperature sudden spike (Z-score: {z_temp:.1f})")

        if violations:
            status = "WARNING"
            diff = 1.0
            if is_door_action:
                msg = (
                    f"C3 Operating deviation during documented physical door action ({current_obs.active_action}): "
                    f"{'; '.join(violations)}. Operational transient, not an uncoordinated attack."
                )
            else:
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

    def check_c4_spatial_consistency(
        self,
        current_obs: WarehouseObservation,
    ) -> ConstraintResult:
        """C4: Spatial Multi-Sensor Consistency Check.
        
        Evaluates physical temperature gradient across multiple active DHT22 sensors.
        In normal sealed cold-room operation, delta across ambient sensors should not exceed threshold.
        """
        sensors = current_obs.sensors
        if not sensors or len(sensors) < 2:
            return ConstraintResult(
                constraint="C4",
                name="Spatial Sensor Consistency",
                status="NOT_APPLICABLE",
                expected=0.0,
                actual=0.0,
                difference=0.0,
                tolerance=self.spatial_delta_temp_max,
                message="C4 Spatial Sensor Consistency not applicable: multi-sensor telemetry not present.",
            )

        active_temps = [
            v["temperature"] for v in sensors.values()
            if v and v.get("temperature") is not None
        ]

        if len(active_temps) < 2:
            return ConstraintResult(
                constraint="C4",
                name="Spatial Sensor Consistency",
                status="INSUFFICIENT_DATA",
                expected=self.spatial_delta_temp_max,
                actual=0.0,
                difference=0.0,
                tolerance=self.spatial_delta_temp_max,
                message="C4 Spatial check insufficient data: fewer than 2 active sensors reporting.",
            )

        delta_temp = round(float(max(active_temps) - min(active_temps)), 2)
        is_door_open = current_obs.active_action == "Door opened"

        if delta_temp > self.spatial_delta_temp_max:
            if is_door_open:
                status = "PASSED"
                msg = (
                    f"C4 Spatial delta elevated ({delta_temp:.1f}°C > {self.spatial_delta_temp_max:.1f}°C) "
                    f"consistently with documented physical door opening event."
                )
            else:
                status = "WARNING"
                msg = (
                    f"C4 Spatial discrepancy: inter-sensor gradient ({delta_temp:.1f}°C) exceeds "
                    f"threshold ({self.spatial_delta_temp_max:.1f}°C) without open door. Sensor fault or spoofing suspected."
                )
        else:
            status = "PASSED"
            msg = f"C4 Spatial consistency satisfied: multi-sensor gradient is {delta_temp:.1f}°C (<= {self.spatial_delta_temp_max:.1f}°C)."

        return ConstraintResult(
            constraint="C4",
            name="Spatial Sensor Consistency",
            status=status,
            expected=self.spatial_delta_temp_max,
            actual=delta_temp,
            difference=max(0.0, delta_temp - self.spatial_delta_temp_max),
            tolerance=self.spatial_delta_temp_max,
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
        c4 = None
        if getattr(current_obs, "sensors", None):
            c4 = self.check_c4_spatial_consistency(current_obs)
            constraints.append(c4)

        custom_results = []
        for invariant in self.custom_invariants:
            try:
                custom_results.append(invariant.check(current_obs, previous_obs))
            except Exception as exc:
                logger.error("Custom invariant %s failed: %s", invariant, exc)

        constraints.extend(custom_results)

        # Only evaluate violated and warning constraints among active applicable ones
        violated = [c.constraint for c in constraints if c.status == "VIOLATED"]
        warnings = [c.constraint for c in constraints if c.status == "WARNING"]

        # Calculate semantic score in [0.0, 1.0]
        # NOT_APPLICABLE constraints contribute 0.0 penalty
        score = 0.0
        if "C1" in violated:
            score += 0.50
        if "C2" in violated:
            score += 0.40
        if "C3" in warnings or "C3" in violated:
            score += 0.15
        if "C4" in warnings or "C4" in violated:
            score += 0.15

        custom_violations = [c for c in custom_results if c.status == "VIOLATED"]
        if custom_violations:
            score += 0.30

        semantic_score = round(min(1.0, score), 2)

        if violated:
            status = "VIOLATION"
            explanation = (
                f"Semantic integrity violations detected ({', '.join(violated)}): "
                f"{'; '.join([c.message for c in constraints if c.status == 'VIOLATED'])}"
            )
        elif warnings:
            status = "WARNING"
            explanation = f"Semantic warning: {'; '.join([c.message for c in constraints if c.status == 'WARNING'])}"
        else:
            status = "NORMAL"
            explanation = "All applicable operational and physical semantic constraints satisfied."

        evidence = {
            "inventory": current_obs.inventory,
            "free_capacity": current_obs.free_capacity,
            "capacity": current_obs.capacity,
            "inbound": current_obs.inbound,
            "outbound": current_obs.outbound,
            "c1_difference": c1.difference,
            "c2_difference": c2.difference,
            "c3_status": c3.status,
            "c4_status": c4.status if c4 else "NOT_APPLICABLE",
            "c4_difference": c4.difference if c4 else 0.0,
            "active_invariant_count": len(self.custom_invariants),
            "custom_invariant_violations": {
                c.constraint: c.difference for c in custom_results if c.status == "VIOLATED"
            },
        }

        return SemanticResult(
            semantic_score=semantic_score,
            status=status,
            constraints=constraints,
            violated_constraints=violated,
            evidence=evidence,
            explanation=explanation,
        )
