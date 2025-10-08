"""Common test utilities for the Sabiana HVAC integration."""

from __future__ import annotations

from unittest.mock import MagicMock

from homeassistant.config_entries import ConfigEntry


class MockConfigEntry(ConfigEntry):
    """Mock config entry for testing."""

    def __init__(
        self,
        *,
        domain: str,
        data: dict | None = None,
        options: dict | None = None,
        title: str | None = None,
        version: int = 1,
        minor_version: int = 1,
        source: str = "user",
        state: str = "not_loaded",
        entry_id: str | None = None,
        discovery_keys: list | None = None,
        unique_id: str | None = None,
    ) -> None:
        """Initialize a mock config entry."""
        super().__init__(
            version=version,
            minor_version=minor_version,
            domain=domain,
            title=title,
            data=data or {},
            options=options or {},
            source=source,
            state=state,
            entry_id=entry_id or "test_entry_id",
            discovery_keys=discovery_keys or [],
            unique_id=unique_id or "test_unique_id",
        )
        self._hass = None

    def add_to_hass(self, hass) -> None:
        """Add this config entry to a Home Assistant instance."""
        self._hass = hass
        hass.config_entries._entries[self.entry_id] = self
