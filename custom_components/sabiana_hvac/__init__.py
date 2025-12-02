"""Sabiana HVAC integration for Home Assistant.

This integration provides climate control for Sabiana HVAC systems.
It uses WebSocket connections for real-time device state updates,
with REST API polling as a fallback.
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
from .const import CONF_LONG_JWT, CONF_SHORT_JWT, DOMAIN
from .coordinator import SabianaDeviceCoordinator, SabianaTokenCoordinator
from .websocket import SabianaWebSocketManager

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.CLIMATE]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up the Sabiana HVAC integration from a config entry."""
    _LOGGER.info("Setting up Sabiana HVAC integration for entry %s", entry.entry_id)

    if CONF_SHORT_JWT not in entry.data or CONF_LONG_JWT not in entry.data:
        _LOGGER.error(
            "Missing JWT tokens in configuration for entry %s",
            entry.entry_id,
        )
        return False

    session = create_session_client(hass)

    coordinator = SabianaTokenCoordinator(hass, session, entry)

    await coordinator.async_config_entry_first_refresh()

    try:
        _LOGGER.debug("Fetching devices from Sabiana API")
        devices = await api.async_get_devices(session, coordinator.short_jwt.token)
        _LOGGER.info("Successfully retrieved %d devices from Sabiana API", len(devices))
    except api.SabianaApiAuthError as err:
        _LOGGER.warning(
            "Authentication failed for entry %s: %s",
            entry.entry_id,
            str(err),
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
        # Create WebSocket manager for real-time updates
        websocket_manager = SabianaWebSocketManager(
            hass,
            lambda: coordinator.short_jwt.token,
        )

        # Try to connect to WebSocket (non-blocking, will reconnect if fails)
        try:
            connected = await websocket_manager.async_connect()
            if connected:
                _LOGGER.info("Connected to Sabiana WebSocket for real-time updates")
            else:
                _LOGGER.warning(
                    "Could not connect to Sabiana WebSocket, "
                    "will use REST API polling with automatic reconnection attempts"
                )
        except Exception:
            _LOGGER.exception(
                "Error connecting to WebSocket, will use REST API polling"
            )

        device_coordinator = SabianaDeviceCoordinator(
            hass,
            session,
            coordinator,
            [device.id for device in devices],
            websocket_manager=websocket_manager,
        )

        await device_coordinator.async_config_entry_first_refresh()

        hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
            "session": session,
            "token_coordinator": coordinator,
            "device_coordinator": device_coordinator,
            "websocket_manager": websocket_manager,
            "devices": devices,
        }
        _LOGGER.debug(
            "Stored data for entry %s: %d devices",
            entry.entry_id,
            len(devices),
        )

        try:
            await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
            _LOGGER.info(
                "Successfully setup Sabiana HVAC integration for entry %s",
                entry.entry_id,
            )
        except Exception:
            _LOGGER.exception("Failed to setup platforms for entry %s", entry.entry_id)
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
                stored_entry = hass.data[DOMAIN].pop(entry.entry_id)

                # Disconnect WebSocket manager
                if websocket_manager := stored_entry.get("websocket_manager"):
                    await websocket_manager.async_disconnect()
                    _LOGGER.debug("Disconnected WebSocket for entry %s", entry.entry_id)

                # Shutdown device coordinator
                if device_coordinator := stored_entry.get("device_coordinator"):
                    await device_coordinator.async_shutdown()

                _LOGGER.debug("Cleaned up data for entry %s", entry.entry_id)
            _LOGGER.info(
                "Successfully unloaded Sabiana HVAC integration for entry %s",
                entry.entry_id,
            )
        else:
            _LOGGER.warning(
                "Failed to unload some platforms for entry %s",
                entry.entry_id,
            )

    except Exception:
        _LOGGER.exception(
            "Error unloading Sabiana HVAC integration for entry %s",
            entry.entry_id,
        )
        return False
    else:
        return unload_ok
