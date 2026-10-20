"""Cold-storage warehouse simulator for organization IoT and operational telemetry.

Simulates cold-storage facility 'W01', generating realistic sensor telemetry (temperature,
humidity), operational inventory levels, total and free capacity, and inbound/outbound
shipment flows with support for deterministic random seeds and historical tracking.
"""

import collections
import logging
import random
from datetime import datetime, timezone
from typing import Deque, List, Optional

from app.config import settings
from app.simulator.models import WarehouseObservation

logger = logging.getLogger("warehouse.simulator")


class ColdStorageWarehouse:
    """Simulates operational and IoT data for cold-storage warehouse W01."""

    def __init__(
        self,
        warehouse_id: str = settings.WAREHOUSE_ID,
        total_capacity: float = settings.DEFAULT_TOTAL_CAPACITY,
        initial_inventory: float = settings.DEFAULT_INITIAL_INVENTORY,
        seed: Optional[int] = settings.DEFAULT_RANDOM_SEED,
        history_size: int = settings.HISTORY_BUFFER_SIZE,
    ):
        if total_capacity <= 0:
            raise ValueError("Total capacity must be greater than zero")
        if initial_inventory < 0 or initial_inventory > total_capacity:
            raise ValueError("Initial inventory must be between 0 and total capacity")

        self.warehouse_id = warehouse_id
        self.total_capacity = float(total_capacity)
        self.initial_inventory = float(initial_inventory)
        self.seed = seed
        self.history_size = history_size

        self.rng = random.Random(seed)
        self.step_count = 0
        self.history: Deque[WarehouseObservation] = collections.deque(maxlen=history_size)

        # Internal state variables
        self.current_inventory = float(initial_inventory)
        self.current_temperature = float(settings.TARGET_TEMPERATURE)
        self.current_humidity = float(settings.TARGET_HUMIDITY)

        # Initialize baseline state
        self._current_observation = self._build_observation(
            inbound=0.0,
            outbound=0.0,
            inventory=self.current_inventory,
            temperature=self.current_temperature,
            humidity=self.current_humidity,
        )
        self.history.append(self._current_observation)
        logger.info(
            f"Initialized ColdStorageWarehouse {self.warehouse_id} (Seed={self.seed}, "
            f"Capacity={self.total_capacity}t, Inventory={self.current_inventory}t)"
        )

    def _build_observation(
        self,
        inbound: float,
        outbound: float,
        inventory: float,
        temperature: float,
        humidity: float,
        is_attack: bool = False,
        attack_type: Optional[str] = None,
    ) -> WarehouseObservation:
        """Construct a validated WarehouseObservation from internal state values."""
        free_capacity = max(0.0, round(self.total_capacity - inventory, 2))
        occupancy = min(100.0, max(0.0, round((inventory / self.total_capacity) * 100, 2)))

        return WarehouseObservation(
            warehouse=self.warehouse_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            step=self.step_count,
            capacity=self.total_capacity,
            inventory=round(inventory, 2),
            free_capacity=free_capacity,
            temperature=round(temperature, 2),
            humidity=round(humidity, 2),
            occupancy=occupancy,
            inbound=round(inbound, 2),
            outbound=round(outbound, 2),
            is_attack_injected=is_attack,
            attack_type=attack_type,
        )

    def step(
        self,
        inbound: Optional[float] = None,
        outbound: Optional[float] = None,
    ) -> WarehouseObservation:
        """Advance the warehouse simulation by one discrete time step.
        
        If inbound or outbound are omitted, stochastic but plausible shipment
        movements are generated, strictly adhering to capacity and non-negative constraints.
        """
        self.step_count += 1

        # 1. Determine shipment flows
        if inbound is None:
            # Generate occasional small inbound shipments (0.0 to 2.0 tons)
            # High chance of no movement to emulate real warehousing cadence
            if self.rng.random() > 0.4:
                max_inbound_headroom = max(0.0, self.total_capacity - self.current_inventory)
                inbound = round(self.rng.uniform(0.5, min(settings.MAX_SHIPMENT_RATE, max(0.5, max_inbound_headroom))), 2)
            else:
                inbound = 0.0

        if outbound is None:
            # Generate occasional small outbound shipments (0.0 to 2.0 tons)
            if self.rng.random() > 0.4:
                max_outbound_available = max(0.0, self.current_inventory)
                outbound = round(self.rng.uniform(0.5, min(settings.MAX_SHIPMENT_RATE, max(0.5, max_outbound_available))), 2)
            else:
                outbound = 0.0

        # 2. Update inventory: current = previous + inbound - outbound
        prev_inventory = self.current_inventory
        new_inventory = prev_inventory + inbound - outbound

        # Enforce physical constraints for normal warehouse operation
        if new_inventory < 0.0:
            outbound = max(0.0, prev_inventory + inbound)
            new_inventory = 0.0
        elif new_inventory > self.total_capacity:
            inbound = max(0.0, self.total_capacity - prev_inventory + outbound)
            new_inventory = self.total_capacity

        self.current_inventory = round(new_inventory, 2)

        # 3. Simulate environmental IoT sensor drift with mean reversion
        # Temperature: mean-reverting random walk towards TARGET_TEMPERATURE (~4.2 °C)
        temp_drift = (settings.TARGET_TEMPERATURE - self.current_temperature) * 0.15
        temp_noise = self.rng.uniform(-0.15, 0.15)
        self.current_temperature = round(
            max(settings.TEMP_MIN_BOUND, min(settings.TEMP_MAX_BOUND, self.current_temperature + temp_drift + temp_noise)),
            2,
        )

        # Humidity: mean-reverting random walk towards TARGET_HUMIDITY (~71.0 %)
        hum_drift = (settings.TARGET_HUMIDITY - self.current_humidity) * 0.12
        hum_noise = self.rng.uniform(-0.6, 0.6)
        self.current_humidity = round(
            max(settings.HUMIDITY_MIN_BOUND, min(settings.HUMIDITY_MAX_BOUND, self.current_humidity + hum_drift + hum_noise)),
            2,
        )

        # 4. Construct and record observation
        obs = self._build_observation(
            inbound=inbound,
            outbound=outbound,
            inventory=self.current_inventory,
            temperature=self.current_temperature,
            humidity=self.current_humidity,
        )

        self._current_observation = obs
        self.history.append(obs)

        logger.debug(
            f"Step {obs.step}: Inv={obs.inventory}t (In={obs.inbound}t, Out={obs.outbound}t), "
            f"Free={obs.free_capacity}t, Temp={obs.temperature}°C, Hum={obs.humidity}%"
        )
        return obs

    def get_current_observation(self) -> WarehouseObservation:
        """Return the most recent observation without advancing time."""
        return self._current_observation

    def get_history(self, limit: int = 50) -> List[WarehouseObservation]:
        """Return the most recent historical observations up to the specified limit."""
        history_list = list(self.history)
        if limit <= 0:
            return []
        return history_list[-limit:]

    def inject_observation(self, observation: WarehouseObservation) -> None:
        """Inject an externally provided observation into the simulator's current state and history.
        
        Used for attack injection testing where the observation is intentionally modified.
        """
        self.step_count = observation.step
        self.current_inventory = observation.inventory
        self.current_temperature = observation.temperature
        self.current_humidity = observation.humidity
        self._current_observation = observation
        self.history.append(observation)
        logger.warning(
            f"Injected observation at step {observation.step}: "
            f"is_attack={observation.is_attack_injected}, type={observation.attack_type}"
        )

    def reset(self, seed: Optional[int] = None) -> None:
        """Reset the warehouse to its baseline state and re-seed RNG."""
        if seed is not None:
            self.seed = seed
        self.rng = random.Random(self.seed)
        self.step_count = 0
        self.current_inventory = float(self.initial_inventory)
        self.current_temperature = float(settings.TARGET_TEMPERATURE)
        self.current_humidity = float(settings.TARGET_HUMIDITY)
        self.history.clear()

        self._current_observation = self._build_observation(
            inbound=0.0,
            outbound=0.0,
            inventory=self.current_inventory,
            temperature=self.current_temperature,
            humidity=self.current_humidity,
        )
        self.history.append(self._current_observation)
        logger.info(f"Reset ColdStorageWarehouse {self.warehouse_id} to baseline (Seed={self.seed})")
