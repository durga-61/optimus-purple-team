"""Global pytest fixtures and test environment configuration.

Tests run against the synthetic simulator by default, so the suite is
deterministic and works on a fresh clone where the real University of
Hohenheim dataset has not been downloaded yet. Tests that genuinely need the
real dataset are marked with ``tests.markers.requires_hohenheim`` and skip
automatically when it is absent.
"""

import os

# Must be set before ``app.config`` is imported: the application default is
# "hohenheim", which would try to open the (possibly missing) real dataset.
os.environ["DATA_SOURCE_MODE"] = "simulator"

import pytest  # noqa: E402
from app.api.state import app_state  # noqa: E402


@pytest.fixture(autouse=True)
def configure_test_state():
    """Default test runs use simulator for deterministic ERP ledger & scenario tests.
    Hohenheim tests explicitly configure HohenheimDataSource."""
    app_state.set_data_source_mode("simulator")
    app_state.reset(seed=42)
    yield
    app_state.reset(seed=42)
