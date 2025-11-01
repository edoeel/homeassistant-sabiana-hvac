"""
Climate entities for Sabiana HVAC systems.

This module provides climate entities that represent Sabiana HVAC devices
as Home Assistant climate entities with full climate control functionality.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, ClassVar

import httpx
from homeassistant.components.climate import (
    ClimateEntity,
    ClimateEntityFeature,
    HVACMode,
)
from homeassistant.components.climate.const import (
    FAN_AUTO,
    FAN_HIGH,
    FAN_LOW,
    FAN_MEDIUM,
    PRESET_NONE,
    PRESET_SLEEP,
)
from homeassistant.const import (
    ATTR_TEMPERATURE,
    UnitOfTemperature,
)
from homeassistant.helpers.restore_state import RestoreEntity

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import api
from .api import SabianaApiAuthError, SabianaApiClientError
from .const import (
    CONF_SHORT_JWT,
    DOMAIN,
    FAN_MODE_MAP,
    HVAC_MODE_MAP,
    SWING_MODE_MAP,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up climate entities for Sabiana HVAC devices."""
    entry_data = hass.data[DOMAIN][entry.entry_id]
    entities = [
        SabianaHvacClimateEntity(entry_data["session"], entry_data[CONF_SHORT_JWT], device)
        for device in entry_data["devices"]
    ]
    async_add_entities(entities)


class SabianaHvacClimateEntity(ClimateEntity, RestoreEntity):
    """
    Climate entity for Sabiana HVAC devices.

    Provides climate control functionality for Sabiana HVAC systems,
    including temperature control, fan modes, swing modes, and presets.
    """

    _attr_hvac_modes: ClassVar[list] = [
        HVACMode.OFF,
        HVACMode.COOL,
        HVACMode.HEAT,
        HVACMode.FAN_ONLY,
    ]
    _attr_fan_modes: ClassVar[list] = [FAN_LOW, FAN_MEDIUM, FAN_HIGH, FAN_AUTO]
    _attr_swing_modes: ClassVar[list] = [
        "Vertical",
        "Horizontal",
        "45 Degrees",
        "Swing",
    ]
    _attr_preset_modes: ClassVar[list] = [PRESET_SLEEP, PRESET_NONE]
    _attr_temperature_unit = UnitOfTemperature.CELSIUS
    _attr_min_temp = 10.0
    _attr_max_temp = 30.0
    _attr_target_temperature_step = 0.5
    _attr_supported_features = (
        ClimateEntityFeature.TARGET_TEMPERATURE
        | ClimateEntityFeature.FAN_MODE
        | ClimateEntityFeature.SWING_MODE
        | ClimateEntityFeature.PRESET_MODE
        | ClimateEntityFeature.TURN_OFF
        | ClimateEntityFeature.TURN_ON
    )
    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(
        self, session: httpx.AsyncClient, short_jwt: str, device: api.SabianaDevice
    ) -> None:
        """
        Initialize the Sabiana HVAC climate entity.

        Args:
            session: HTTP client session for API calls.
            short_jwt: Short-term JWT for API requests.
            device: Sabiana device information.

        """
        self._session = session
        self._short_jwt = short_jwt
        self._device = device
        self._attr_unique_id = device.id
        self._attr_name = device.name

        self._attr_hvac_mode = HVACMode.OFF
        self._attr_target_temperature = 25.0
        self._attr_fan_mode = FAN_AUTO
        self._attr_swing_mode = "Swing"
        self._attr_preset_mode = None

    def _celsius_to_hex(self, temp: float) -> str:
        converted_value = int(temp * 10)
        return f"{converted_value:04x}"

    def _map_fan_mode_to_sabiana_char(self, fan_mode: str | None) -> str:
        return FAN_MODE_MAP.get(fan_mode, "4")

    def _map_hvac_mode_to_sabiana_char(self, hvac_mode: HVACMode | None) -> str:
        return HVAC_MODE_MAP.get(hvac_mode, "4")

    def _map_swing_mode_to_sabiana_char(self, swing_mode: str | None) -> str:
        return SWING_MODE_MAP.get(swing_mode, "4")

    def _map_preset_mode_to_sabiana_char(self, preset_mode: str | None) -> str:
        return "2" if preset_mode == PRESET_SLEEP else "0"

    def _build_command_payload(self) -> str:
        fan = self._map_fan_mode_to_sabiana_char(self.fan_mode)
        mode = self._map_hvac_mode_to_sabiana_char(self.hvac_mode)
        temperature = self._celsius_to_hex(self.target_temperature)
        swing = self._map_swing_mode_to_sabiana_char(self.swing_mode)
        preset = self._map_preset_mode_to_sabiana_char(self.preset_mode)

        return f"0{fan}0{mode}{temperature}0{swing}01FFFF000{preset}"

    async def _async_execute_command(self) -> None:
        command_payload = self._build_command_payload()

        try:
            await api.async_send_command(
                self._session, self._short_jwt, self._device.id, command_payload
            )
            self.async_write_ha_state()
        except SabianaApiAuthError:
            _LOGGER.exception(
                "Authentication error for %s. Please re-configure the integration.",
                self.name,
            )
        except SabianaApiClientError:
            _LOGGER.exception("API error while sending command to %s", self.name)
        except httpx.RequestError:
            _LOGGER.exception("Connection error while sending command to %s", self.name)
        except Exception:
            _LOGGER.exception("Unexpected error while sending command to %s", self.name)

    async def async_added_to_hass(self) -> None:
        """
        Handle entity being added to Home Assistant.

        Restores the last known state from Home Assistant.
        """
        await super().async_added_to_hass()
        if last_state := await self.async_get_last_state():
            self._attr_hvac_mode = last_state.state
            self._attr_target_temperature = last_state.attributes.get(ATTR_TEMPERATURE)
            self._attr_fan_mode = last_state.attributes.get("fan_mode")
            self._attr_swing_mode = last_state.attributes.get("swing_mode")
            self._attr_preset_mode = last_state.attributes.get("preset_mode")
            _LOGGER.debug("Restored state for %s", self.name)

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        """
        Set the HVAC mode.

        Args:
            hvac_mode: The HVAC mode to set.

        """
        self._attr_hvac_mode = hvac_mode
        await self._async_execute_command()

    async def async_set_temperature(self, **kwargs: Any) -> None:
        """
        Set the target temperature.

        Args:
            **kwargs: Keyword arguments containing temperature data.

        """
        self._attr_target_temperature = kwargs.get(ATTR_TEMPERATURE)
        self.async_write_ha_state()

        if self.hvac_mode != HVACMode.OFF and self._attr_target_temperature is not None:
            await self._async_execute_command()

    async def async_set_fan_mode(self, fan_mode: str) -> None:
        """
        Set the fan mode.

        Args:
            fan_mode: The fan mode to set.

        """
        self._attr_fan_mode = fan_mode
        self.async_write_ha_state()

        if self.hvac_mode != HVACMode.OFF:
            await self._async_execute_command()

    async def async_set_swing_mode(self, swing_mode: str) -> None:
        """
        Set the swing mode.

        Args:
            swing_mode: The swing mode to set.

        """
        self._attr_swing_mode = swing_mode
        self.async_write_ha_state()

        if self.hvac_mode != HVACMode.OFF:
            await self._async_execute_command()

    async def async_set_preset_mode(self, preset_mode: str | None) -> None:
        """
        Set the preset mode.

        Args:
            preset_mode: The preset mode to set, or None to clear.

        """
        self._attr_preset_mode = preset_mode
        self.async_write_ha_state()

        if self.hvac_mode != HVACMode.OFF:
            await self._async_execute_command()

    async def async_turn_on(self) -> None:
        """Turn the device on by setting to fan-only mode."""
        await self.async_set_hvac_mode(HVACMode.FAN_ONLY)

    async def async_turn_off(self) -> None:
        """Turn the device off by setting to off mode."""
        await self.async_set_hvac_mode(HVACMode.OFF)
