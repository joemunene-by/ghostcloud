"""Shared pytest fixtures for ghostcloud tests."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def aws_vulnerable() -> Path:
    return FIXTURES / "aws_vulnerable.json"


@pytest.fixture
def aws_clean() -> Path:
    return FIXTURES / "aws_clean.json"


@pytest.fixture
def gcp_vulnerable() -> Path:
    return FIXTURES / "gcp_vulnerable.json"


@pytest.fixture
def gcp_clean() -> Path:
    return FIXTURES / "gcp_clean.json"


@pytest.fixture
def azure_vulnerable() -> Path:
    return FIXTURES / "azure_vulnerable.json"


@pytest.fixture
def azure_clean() -> Path:
    return FIXTURES / "azure_clean.json"


@pytest.fixture
def malformed() -> Path:
    return FIXTURES / "malformed.json"
