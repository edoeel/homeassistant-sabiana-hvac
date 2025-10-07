"""
Sabiana HVAC integration for Home Assistant.

This integration provides climate control for Sabiana HVAC systems.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx
from homeassistant.const import Platform

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant

from . import api
from .api import create_session_client
from .const import CONF_TOKEN, DOMAIN

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.CLIMATE]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up the Sabiana HVAC integration from a config entry."""
    _LOGGER.info("Setting up Sabiana HVAC integration for entry %s", entry.entry_id)

    if CONF_TOKEN not in entry.data:
        _LOGGER.error("Missing token in configuration for entry %s", entry.entry_id)
        return False

    session = create_session_client(hass)
    token = entry.data[CONF_TOKEN]

    try:
        _LOGGER.debug("Fetching devices from Sabiana API")
        devices = await api.async_get_devices(session, token)
        _LOGGER.info("Successfully retrieved %d devices from Sabiana API", len(devices))
    except api.SabianaApiAuthError as err:
        _LOGGER.warning(
            "Authentication failed for entry %s: %s", entry.entry_id, str(err)
        )
    except api.SabianaApiClientError:
        _LOGGER.exception("API client error for entry %s", entry.entry_id)
    except httpx.ConnectError:
        _LOGGER.exception("Connection error for entry %s", entry.entry_id)
    except httpx.TimeoutException:
        _LOGGER.exception("Timeout error for entry %s", entry.entry_id)
    except Exception:
        _LOGGER.exception("Unexpected error during setup for entry %s", entry.entry_id)
    else:
        hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
            "session": session,
            "token": token,
            "devices": devices,
        }
        _LOGGER.debug(
            "Stored data for entry %s: %d devices", entry.entry_id, len(devices)
        )

        try:
            await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
            _LOGGER.info(
                "Successfully setup Sabiana HVAC integration for entry %s",
                entry.entry_id,
            )
        except Exception:
            _LOGGER.exception("Failed to setup platforms for entry %s", entry.entry_id)
            return False
        else:
            return True

    return False


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload the Sabiana HVAC integration from a config entry."""
    _LOGGER.info("Unloading Sabiana HVAC integration for entry %s", entry.entry_id)

    try:
        unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
        if unload_ok:
            if DOMAIN in hass.data and entry.entry_id in hass.data[DOMAIN]:
                hass.data[DOMAIN].pop(entry.entry_id)
                _LOGGER.debug("Cleaned up data for entry %s", entry.entry_id)
            _LOGGER.info(
                "Successfully unloaded Sabiana HVAC integration for entry %s",
                entry.entry_id,
            )
        else:
            _LOGGER.warning(
                "Failed to unload some platforms for entry %s", entry.entry_id
            )

    except Exception:
        _LOGGER.exception(
            "Error unloading Sabiana HVAC integration for entry %s",
            entry.entry_id,
        )
        return False
    else:
        return unload_ok
