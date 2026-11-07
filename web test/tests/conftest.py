"""Configuración y fixtures para pruebas unitarias de WebSec Auditor."""

import pytest
from websec.config import ScanConfig
from websec.core.models import Target

@pytest.fixture
def sample_target() -> Target:
    return Target("https://example.com")

@pytest.fixture
def sample_config(sample_target: Target) -> ScanConfig:
    return ScanConfig(
        target_url=sample_target.url,
        has_permission=True,
        rate_limit=100.0,  # Acelerar tests
        timeout=2.0,
        max_retries=1,
    )
