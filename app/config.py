"""Central application configuration.

Uses Pydantic BaseSettings to read configuration from environment variables or .env file,
falling back to sensible defaults for local execution.
"""

from pathlib import Path
from typing import Optional, Tuple
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppSettings(BaseSettings):
    """Central configuration for the Organization Information Security Platform."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # General Settings
    APP_NAME: str = "Cold-Storage Security Monitor: Data Integrity Monitoring Platform"
    APP_VERSION: str = "3.1.0"
    DEBUG: bool = False
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # Data Source Architecture Settings
    DATA_SOURCE_MODE: str = "hohenheim"  # "hohenheim" or "simulator"
    HOHENHEIM_DB_PATH: str = "data/processed/hohenheim/hohenheim_synchronized.db"
    HOHENHEIM_RAW_DIR: str = "data/raw/hohenheim"
    ENVIRONMENTAL_DELTA_T_MAX: float = 5.0  # Max degrees C inter-sensor discrepancy
    ENVIRONMENTAL_DELTA_H_MAX: float = 25.0  # Max % RH inter-sensor discrepancy

    # Simulator Settings (retained for isolated testing / purple benchmarking)
    SIMULATION_INTERVAL_SECONDS: float = 2.0
    DEFAULT_RANDOM_SEED: Optional[int] = 42
    WAREHOUSE_ID: str = "W01"
    DEFAULT_TOTAL_CAPACITY: float = 50.0  # Tons
    DEFAULT_INITIAL_INVENTORY: float = 42.0  # Tons
    TARGET_TEMPERATURE: float = 4.2  # Celsius
    TEMP_MIN_BOUND: float = 1.0
    TEMP_MAX_BOUND: float = 7.0
    TARGET_HUMIDITY: float = 71.0  # Percentage
    HUMIDITY_MIN_BOUND: float = 60.0
    HUMIDITY_MAX_BOUND: float = 85.0
    MAX_SHIPMENT_RATE: float = 2.5  # Max tons per step for inbound/outbound
    HISTORY_BUFFER_SIZE: int = 100

    # Semantic Tolerance Settings (C1, C2, C3)
    C1_CAPACITY_TOLERANCE: float = 0.5  # Tons discrepancy threshold
    C2_FLOW_TOLERANCE: float = 0.5  # Tons discrepancy threshold
    C3_HISTORICAL_TEMP_RANGE: Tuple[float, float] = (1.0, 7.0)
    C3_HISTORICAL_HUMIDITY_RANGE: Tuple[float, float] = (60.0, 85.0)

    # Temporal Settings
    TEMPORAL_WINDOW_SIZE: int = 10
    TEMPORAL_DECAY_FACTOR: float = 0.85

    # Joint Decision Fusion Settings
    DECISION_WEIGHT_SEMANTIC: float = 0.40
    DECISION_WEIGHT_TEMPORAL: float = 0.25
    DECISION_WEIGHT_STRUCTURAL: float = 0.20
    DECISION_WEIGHT_ML: float = 0.15
    DECISION_PRIMARY_RISK_THRESHOLD: float = 0.40
    DECISION_SUSPICIOUS_RISK_THRESHOLD: float = 0.20

    # Adaptive Fusion & Dynamic Invariant Mining (trusted-label experiments)
    ADAPTIVE_FUSION_MAX_FPR: float = 0.001
    ADAPTIVE_FUSION_SEED: int = 42
    INVARIANT_MIN_NORMAL_COVERAGE: float = 0.999
    INVARIANT_MAX_FPR: float = 0.001
    INVARIANT_MIN_ATTACK_DETECTION: float = 0.02
    INVARIANT_REDUNDANCY_JACCARD: float = 0.95

    # Security & API Protection Settings
    ATTACK_GATEWAY_TOKEN: Optional[str] = None
    OPERATOR_TOKEN: Optional[str] = None
    GATEWAY_EXPOSE_CLASSIFICATION: bool = False
    LOCAL_DEMO_MODE: bool = True
    ALLOWED_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]


settings = AppSettings()
