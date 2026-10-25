"""Shared pytest markers for tests that depend on external resources."""

import pytest

from app.data_sources.hohenheim import hohenheim_dataset_available

requires_hohenheim = pytest.mark.skipif(
    not hohenheim_dataset_available(),
    reason=(
        "University of Hohenheim dataset not prepared; "
        "run `python scripts/fetch_dataset.py` to enable this test"
    ),
)
