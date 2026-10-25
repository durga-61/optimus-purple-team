"""Global pytest fixtures and test environment configuration.

Ensures deterministic test execution across both data source modes
(University of Hohenheim real dataset playback and cold-storage warehouse simulator).
"""

import pytest
from app.api.state import app_state


@pytest.fixture(autouse=True)
def configure_test_state():
    """Default test runs use simulator for deterministic ERP ledger & scenario tests.
    Hohenheim tests explicitly configure HohenheimDataSource."""
    app_state.set_data_source_mode("simulator")
    app_state.reset(seed=42)
    yield
    app_state.reset(seed=42)
