"""University of Hohenheim Cold-Storage Room Monitoring Dataset Adapter.

Loads, synchronizes, and replays real-world time-series data from 9 DHT22 sensors
deployed in a cold storage facility, accompanied by physical experimental action logs
(Zenodo Record 15130001, DOI: 10.5281/zenodo.15130001, CC-BY-4.0).
"""

import collections
import logging
import os
from pathlib import Path
import sqlite3
import threading
from typing import Any, Deque, Dict, List, Optional

import numpy as np
import pandas as pd

from app.config import settings
from app.data_sources.base import BaseDataSource
from app.simulator.models import WarehouseObservation

logger = logging.getLogger("data_sources.hohenheim")

DATASET_METADATA = {
    "title": "Temperature and Humidity Time Series of Cold Storage Room Monitoring",
    "authors": ["Elia Henrichs", "Florian Stoll", "Christian Krupitzer"],
    "institution": "Department of Food Informatics, University of Hohenheim",
    "doi": "10.5281/zenodo.15130001",
    "url": "https://zenodo.org/records/15130001",
    "license": "Creative Commons Attribution 4.0 International (CC-BY-4.0)",
    "publication_year": 2025,
    "sampling_rate_seconds": 5.0,
    "sensor_model": "DHT22 Digital Temperature & Humidity",
    "num_sensors": 9,
    "is_real_dataset": True,
    "has_inventory_ledger": False,
    "has_shipment_ledger": False,
}

SENSOR_IDS = [f"SENSOR0{i}" for i in range(1, 10)]


class HohenheimDataSource(BaseDataSource):
    """Deterministic playback adapter for the 9-sensor Hohenheim cold storage dataset."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        raw_dir: Optional[str] = None,
        history_size: int = 100,
    ):
        self._lock = threading.RLock()
        self.history_size = history_size
        self.history: Deque[WarehouseObservation] = collections.deque(maxlen=history_size)

        project_root = Path(__file__).resolve().parent.parent.parent
        self.db_path = Path(db_path) if db_path else project_root / settings.HOHENHEIM_DB_PATH
        self.raw_dir = Path(raw_dir) if raw_dir else project_root / settings.HOHENHEIM_RAW_DIR
        self.warehouse_id = settings.WAREHOUSE_ID

        self._ensure_database_ready()

        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

        # Query total count
        cur = self._conn.cursor()
        cur.execute("SELECT COUNT(*) FROM observations;")
        self.total_records = cur.fetchone()[0]

        self.current_cursor: int = 0
        self.current_observation: Optional[WarehouseObservation] = None

        # Load first observation
        self._load_observation(0)
        logger.info(
            f"Initialized HohenheimDataSource with {self.total_records} synchronized 9-sensor records."
        )

    def _ensure_database_ready(self) -> None:
        """Verify SQLite cache exists, building it from preprocessed CSVs if missing."""
        if self.db_path.exists() and self.db_path.stat().st_size > 100000:
            return

        logger.info(f"Hohenheim database not found at {self.db_path}. Auto-building from raw CSVs...")
        prep_dir = self.raw_dir / "preprocessed"
        if not prep_dir.exists():
            raise FileNotFoundError(
                f"Cannot build Hohenheim database: Preprocessed directory not found at {prep_dir}."
            )

        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        df_base = pd.read_csv(prep_dir / "SENSOR01_preprocessed.csv", sep=";")
        dt_series = pd.to_datetime(df_base["Date"] + " " + df_base["Time"], format="%d.%m.%Y %H:%M:%S")

        df_sync = pd.DataFrame()
        df_sync["timestamp"] = dt_series.dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        df_sync["step"] = range(len(df_base))

        for i in range(1, 10):
            df_s = pd.read_csv(prep_dir / f"SENSOR0{i}_preprocessed.csv", sep=";")
            df_sync[f"temp_s{i}"] = df_s["Temperature"]
            df_sync[f"hum_s{i}"] = df_s["Humidity"]

        actions_file = self.raw_dir / "experiment_actions.csv"
        active_actions = np.array([None] * len(df_sync), dtype=object)
        if actions_file.exists():
            actions_df = pd.read_csv(actions_file, sep=";")
            actions_df["start_dt"] = pd.to_datetime(actions_df["Date"] + " " + actions_df["Start Time"], format="%Y-%m-%d %H:%M:%S")
            actions_df["end_dt"] = pd.to_datetime(actions_df["Date"] + " " + actions_df["End Time"], format="%Y-%m-%d %H:%M:%S")
            dt_values = dt_series.values
            for _, row in actions_df.iterrows():
                mask = (dt_values >= row["start_dt"].to_numpy()) & (dt_values <= row["end_dt"].to_numpy())
                active_actions[mask] = row["Action"]

        df_sync["active_action"] = active_actions

        conn = sqlite3.connect(str(self.db_path))
        df_sync.to_sql("observations", conn, index=False)
        conn.execute("CREATE UNIQUE INDEX idx_step ON observations(step);")
        conn.execute("CREATE INDEX idx_timestamp ON observations(timestamp);")
        conn.commit()
        conn.close()
        logger.info(f"Hohenheim synchronized database built at {self.db_path} ({len(df_sync)} steps).")

    def _row_to_observation(self, row: sqlite3.Row) -> WarehouseObservation:
        """Convert a synchronized SQLite row into a structured WarehouseObservation."""
        sensors = {}
        active_sensors = []
        missing_sensors = []
        temps = []
        hums = []

        for i in range(1, 10):
            s_name = f"SENSOR0{i}"
            t_val = row[f"temp_s{i}"]
            h_val = row[f"hum_s{i}"]

            t_float = round(float(t_val), 2) if t_val is not None else None
            h_float = round(float(h_val), 2) if h_val is not None else None

            sensors[s_name] = {
                "temperature": t_float,
                "humidity": h_float,
            }

            if t_float is not None and h_float is not None:
                active_sensors.append(s_name)
                temps.append(t_float)
                hums.append(h_float)
            else:
                missing_sensors.append(s_name)

        # Primary cold storage temperature & humidity representation
        # Use SENSOR01 (primary room monitor) if healthy; otherwise spatial mean
        if sensors["SENSOR01"]["temperature"] is not None:
            primary_temp = sensors["SENSOR01"]["temperature"]
            primary_hum = sensors["SENSOR01"]["humidity"]
        elif temps:
            primary_temp = round(float(np.mean(temps)), 2)
            primary_hum = round(float(np.mean(hums)), 2)
        else:
            primary_temp = settings.TARGET_TEMPERATURE
            primary_hum = settings.TARGET_HUMIDITY

        # Quality metrics
        temp_delta = round(float(max(temps) - min(temps)), 2) if len(temps) > 1 else 0.0
        hum_delta = round(float(max(hums) - min(hums)), 2) if len(hums) > 1 else 0.0

        quality = {
            "total_sensors": 9,
            "active_sensor_count": len(active_sensors),
            "missing_sensor_count": len(missing_sensors),
            "active_sensors": active_sensors,
            "missing_sensors": missing_sensors,
            "has_missing_data": len(missing_sensors) > 0,
            "inter_sensor_temp_delta": temp_delta,
            "inter_sensor_hum_delta": hum_delta,
            "spatial_temp_std": round(float(np.std(temps)), 2) if len(temps) > 1 else 0.0,
        }

        action = row["active_action"]

        obs = WarehouseObservation(
            warehouse=settings.WAREHOUSE_ID,
            timestamp=row["timestamp"],
            step=int(row["step"]),
            temperature=primary_temp,
            humidity=primary_hum,
            # Ledger fields unavailable in pure environmental dataset
            capacity=None,
            inventory=None,
            free_capacity=None,
            occupancy=None,
            inbound=None,
            outbound=None,
            # Metadata
            source="hohenheim",
            is_recorded_playback=True,
            dataset_name=DATASET_METADATA["title"],
            sensors=sensors,
            active_action=action,
            data_quality=quality,
            is_attack_injected=False,
            attack_type=None,
        )
        return obs

    def _load_observation(self, step: int) -> WarehouseObservation:
        """Retrieve and cache the observation at specified discrete step."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM observations WHERE step = ?;", (step,))
        row = cursor.fetchone()
        if row is None:
            raise IndexError(f"Playback step {step} out of bounds [0, {self.total_records - 1}]")

        obs = self._row_to_observation(row)
        self.current_cursor = step
        self.current_observation = obs
        self.history.append(obs)
        return obs

    def get_metadata(self) -> Dict[str, Any]:
        return {
            **DATASET_METADATA,
            "total_records": self.total_records,
            "playback_cursor": self.current_cursor,
        }

    @property
    def step_count(self) -> int:
        return self.current_cursor

    def get_available_sensors(self) -> List[str]:
        return SENSOR_IDS

    def get_current_observation(self) -> WarehouseObservation:
        with self._lock:
            if self.current_observation is None:
                return self._load_observation(self.current_cursor)
            return self.current_observation

    def step(self, *args, **kwargs) -> WarehouseObservation:
        with self._lock:
            next_step = self.current_cursor + 1
            if next_step >= self.total_records:
                logger.info("Reached end of Hohenheim dataset playback. Looping to beginning.")
                next_step = 0
            return self._load_observation(next_step)

    def seek(self, step: int) -> WarehouseObservation:
        with self._lock:
            if step < 0 or step >= self.total_records:
                raise ValueError(
                    f"Invalid seek target {step}. Must be in range [0, {self.total_records - 1}]."
                )
            return self._load_observation(step)

    def reset(self, seed: Optional[int] = None) -> WarehouseObservation:
        with self._lock:
            self.history.clear()
            return self._load_observation(0)

    def get_history(self, limit: int = 50) -> List[WarehouseObservation]:
        with self._lock:
            items = list(self.history)
            return items[-limit:] if limit > 0 else items

    def get_window(self, start_step: int, window_size: int = 20) -> List[WarehouseObservation]:
        """Retrieve consecutive observations starting at start_step up to window_size."""
        with self._lock:
            start = max(0, min(start_step, self.total_records - 1))
            size = max(1, min(window_size, 200))
            end = min(self.total_records, start + size)
            cur = self._conn.cursor()
            cur.execute("SELECT * FROM observations WHERE step >= ? AND step < ? ORDER BY step ASC;", (start, end))
            rows = cur.fetchall()
            return [self._row_to_observation(r) for r in rows]

    def get_playback_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "source": "hohenheim",
                "is_recorded_playback": True,
                "current_step": self.current_cursor,
                "total_records": self.total_records,
                "progress_percent": round((self.current_cursor / max(1, self.total_records - 1)) * 100, 2),
                "timestamp": self.current_observation.timestamp if self.current_observation else None,
                "active_action": self.current_observation.active_action if self.current_observation else None,
            }

    def inject_observation(self, obs: WarehouseObservation) -> None:
        """Inject a manipulated observation into the playback pipeline for controlled attack testing."""
        with self._lock:
            self.current_observation = obs
            self.history.append(obs)

    def close(self) -> None:
        """Cleanly close underlying SQLite database connection."""
        with self._lock:
            if hasattr(self, "_conn") and self._conn:
                try:
                    self._conn.close()
                except Exception:
                    pass
