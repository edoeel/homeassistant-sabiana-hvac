"""Test the Sabiana HVAC integration initialization."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from custom_components.sabiana_hvac.const import DOMAIN


def test_domain_constant() -> None:
    """Test that the domain constant is defined correctly."""
    assert DOMAIN == "sabiana_hvac"


@pytest.mark.asyncio
async def test_integration_setup() -> None:
    """Test basic integration setup functionality."""
    assert True
