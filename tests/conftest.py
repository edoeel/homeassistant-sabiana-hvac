"""Test configuration for the Sabiana HVAC integration."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

import pytest

from custom_components.sabiana_hvac.const import DOMAIN
from tests.common import MockConfigEntry

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant


@pytest.fixture
def hass() -> "HomeAssistant":
    """Return a Home Assistant instance for testing."""
    from homeassistant.core import HomeAssistant

    hass = HomeAssistant("")
    hass.config_entries = MockConfigEntries()
    hass.data = {}
    return hass


class MockConfigEntries:
    """Mock config entries for testing."""

    def __init__(self) -> None:
        """Initialize mock config entries."""
        self._entries = {}

    def async_entries(self, domain: str | None = None) -> list:
        """Return config entries, optionally filtered by domain."""
        if domain:
            return [entry for entry in self._entries.values() if entry.domain == domain]
        return list(self._entries.values())

    async def async_setup(self, entry_id: str) -> bool:
        """Mock setup of a config entry."""
        return True

    async def async_unload_platforms(
        self, entry: MockConfigEntry, platforms: list
    ) -> bool:
        """Mock unload of platforms."""
        return True


@pytest.fixture
def mock_setup_entry() -> AsyncMock:
    """Override async_setup_entry."""
    with patch(
        "custom_components.sabiana_hvac.async_setup_entry",
        return_value=True,
    ) as mock_setup:
        yield mock_setup


@pytest.fixture
def mock_config_entry() -> MockConfigEntry:
    """Return a mock config entry."""
    return MockConfigEntry(
        domain=DOMAIN,
        data={
            "token": "test_token_12345",
        },
        title="Test Sabiana HVAC",
    )


@pytest.fixture
async def init_integration(
    hass: "HomeAssistant",
    mock_config_entry: MockConfigEntry,
    mock_setup_entry: AsyncMock,
) -> MockConfigEntry:
    """Set up the Sabiana HVAC integration for testing."""
    mock_config_entry.add_to_hass(hass)
    await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()
    return mock_config_entry
