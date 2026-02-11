"""Climate entities for Sabiana HVAC systems.

This module provides climate entities that represent Sabiana HVAC devices
as Home Assistant climate entities with full climate control functionality.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Any

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
    DOMAIN,
    FAN_MODE_MAP,
    HVAC_MODE_MAP,
    SWING_MODE_MAP,
)

if TYPE_CHECKING:
    from .coordinator import SabianaDeviceCoordinator, SabianaTokenCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up climate entities for Sabiana HVAC devices."""
    entry_data = hass.data[DOMAIN][entry.entry_id]
    token_coordinator = entry_data["token_coordinator"]
    device_coordinator = entry_data["device_coordinator"]

    entities = [
        SabianaHvacClimateEntity(
            entry_data["session"],
            token_coordinator,
            device_coordinator,
            device,
        )
        for device in entry_data["devices"]
    ]
    async_add_entities(entities)


class SabianaHvacClimateEntity(ClimateEntity, RestoreEntity):
    """Climate entity for Sabiana HVAC devices.

    Provides climate control functionality for Sabiana HVAC systems,
    including temperature control, fan modes, swing modes, and presets.
    """

    _attr_temperature_unit = UnitOfTemperature.CELSIUS
    _attr_target_temperature_step = 0.5
    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(
        self,
        session: httpx.AsyncClient,
        token_coordinator: SabianaTokenCoordinator,
        device_coordinator: SabianaDeviceCoordinator,
        device: api.SabianaDevice,
    ) -> None:
        """Initialize the Sabiana HVAC climate entity.

        Args:
            session: HTTP client session for API calls.
            token_coordinator: Token coordinator for managing JWT tokens.
            device_coordinator: Device coordinator for polling device states.
            device: Sabiana device information.

        """
        self._session = session
        self._coordinator = token_coordinator
        self._device_coordinator = device_coordinator
        self._device = device
        self._attr_unique_id = device.id
        self._attr_name = device.name

        self._attr_hvac_mode = HVACMode.OFF
        self._attr_target_temperature = 25.0
        self._attr_fan_mode = FAN_AUTO
        self._attr_swing_mode = "off"  # Default to off instead of "Swing"
        self._attr_preset_mode = PRESET_NONE  # Initialize to PRESET_NONE, not None
        self._coordinator_listener_unsub = None

        # Optimistic state handling: Track when we last sent a command
        # to prevent coordinator from immediately overwriting the UI
        self._last_command_time = 0.0
        self._refresh_task: asyncio.Task[None] | None = None
        self._optimistic_update_duration = 10.0  # Keep optimistic state for 10 seconds

        # Configure entity features
        self._configure_features()

        # Debug logging to verify preset mode configuration
        _LOGGER.info(
            "Initialized %s with preset_mode=%s, preset_modes=%s, features=%s",
            self.name,
            self._attr_preset_mode,
            self._attr_preset_modes,
            self._attr_supported_features,
        )

    def _configure_features(self) -> None:
        """Configure entity features for Sabiana HVAC devices."""
        self._attr_hvac_modes = [
            HVACMode.OFF,
            HVACMode.COOL,
            HVACMode.HEAT,
            HVACMode.DRY,
            HVACMode.FAN_ONLY,
        ]
        self._attr_fan_modes = [FAN_LOW, FAN_MEDIUM, FAN_HIGH, FAN_AUTO]
        self._attr_swing_modes = []  # Swing mode not currently supported
        # Preset modes - Sabiana devices support sleep/night mode
        self._attr_preset_modes = [PRESET_NONE, PRESET_SLEEP]
        self._attr_supported_features = (
            ClimateEntityFeature.TARGET_TEMPERATURE
            | ClimateEntityFeature.FAN_MODE
            | ClimateEntityFeature.PRESET_MODE  # Enable preset mode by default
            | ClimateEntityFeature.TURN_OFF
            | ClimateEntityFeature.TURN_ON
        )
        self._attr_min_temp = 10.0
        self._attr_max_temp = 30.0

    def _celsius_to_hex(self, temp: float) -> str:
        converted_value = int(temp * 10)
        return f"{converted_value:04x}"

    @property
    def preset_mode(self) -> str | None:
        """Return the current preset mode."""
        return self._attr_preset_mode

    @property
    def preset_modes(self) -> list[str]:
        """Return a list of available preset modes."""
        # CRITICAL: Must always return a list, never None, or HA won't show the control
        if hasattr(self, "_attr_preset_modes") and self._attr_preset_modes:
            return self._attr_preset_modes
        # Fallback to ensure preset modes are always available
        return [PRESET_NONE, PRESET_SLEEP]

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
        """Execute command with optimistic state update."""
        command_payload = self._build_command_payload()

        try:
            # STEP 1: Mark command time for optimistic state handling
            # This prevents coordinator from overwriting our commanded value immediately
            self._last_command_time = time.monotonic()

            # Send the command to the device
            await api.async_send_command(
                self._session,
                self._coordinator.short_jwt.token,
                self._device.id,
                command_payload,
            )

            # STEP 2: Update state immediately (optimistic)
            # The UI will show the new value right away
            self.async_write_ha_state()

            # STEP 3: Schedule delayed refresh (5 seconds)
            # Give the device time to process before fetching new state
            self._refresh_task = asyncio.create_task(self._async_delayed_refresh())

        except SabianaApiAuthError:
            _LOGGER.exception(
                "Authentication error for %s. Please re-configure the integration.",
                self.name,
            )
            self._last_command_time = 0.0  # Reset on error
        except SabianaApiClientError:
            _LOGGER.exception("API error while sending command to %s", self.name)
            self._last_command_time = 0.0  # Reset on error
        except httpx.RequestError:
            _LOGGER.exception("Connection error while sending command to %s", self.name)
            self._last_command_time = 0.0  # Reset on error
        except Exception:
            _LOGGER.exception("Unexpected error while sending command to %s", self.name)
            self._last_command_time = 0.0  # Reset on error

    async def _async_delayed_refresh(self) -> None:
        """Request coordinator refresh after a delay to allow device processing."""
        await asyncio.sleep(5)  # Wait 5 seconds
        await self._device_coordinator.async_request_refresh()

    async def async_added_to_hass(self) -> None:
        """Handle entity being added to Home Assistant.

        Restores the last known state from HA and subscribes to device updates.
        """
        await super().async_added_to_hass()

        # Subscribe to device coordinator updates
        self._coordinator_listener_unsub = self._device_coordinator.async_add_listener(
            self._handle_coordinator_update
        )

        # Try to get current state from coordinator first
        if (
            self._device_coordinator.data
            and self._device.id in self._device_coordinator.data
        ):
            self._update_from_coordinator()
        # Otherwise restore last known state if available
        elif last_state := await self.async_get_last_state():
            # Map string state to HVACMode
            try:
                self._attr_hvac_mode = HVACMode(last_state.state)
            except ValueError:
                self._attr_hvac_mode = HVACMode.OFF
            self._attr_target_temperature = last_state.attributes.get(ATTR_TEMPERATURE)
            self._attr_fan_mode = last_state.attributes.get("fan_mode")
            self._attr_swing_mode = last_state.attributes.get("swing_mode")
            self._attr_preset_mode = last_state.attributes.get("preset_mode")
            _LOGGER.debug("Restored state for %s", self.name)

    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self._update_from_coordinator()
        self.async_write_ha_state()

    def _update_from_coordinator(self) -> None:
        """Update entity state from coordinator data."""
        if not self._device_coordinator.data:
            _LOGGER.debug("%s: No coordinator data", self.name)
            return

        device_state = self._device_coordinator.data.get(self._device.id)
        if not device_state:
            _LOGGER.debug("%s: No device state in coordinator data", self.name)
            return

        # Log what we received from coordinator
        _LOGGER.debug(
            "%s: Coordinator data - fan_mode=%s, preset_mode=%s, hvac_mode=%s, temp=%s",
            self.name,
            device_state.fan_mode,
            device_state.preset_mode,
            device_state.hvac_mode,
            device_state.target_temperature,
        )

        # Check if we recently sent a command - keep optimistic state
        time_since_command = time.monotonic() - self._last_command_time
        in_optimistic_window = time_since_command < self._optimistic_update_duration

        if in_optimistic_window:
            self._update_optimistic_state(device_state, time_since_command)
            return

        # Past optimistic window - update all state from device
        self._update_full_state(device_state)

    def _update_optimistic_state(
        self, device_state: api.SabianaDeviceState, time_since_command: float
    ) -> None:
        """Update state during optimistic window (after user command)."""
        _LOGGER.debug(
            "In optimistic window for %s (%.1fs since command)",
            self.name,
            time_since_command,
        )
        # Always update current temperature (read-only, measured value)
        if device_state.current_temperature is not None:
            self._attr_current_temperature = device_state.current_temperature

        # Allow fan_mode and preset_mode to update during optimistic window
        # These can be changed externally (from Sabiana app) and must sync
        if device_state.fan_mode is not None:
            old_fan = self._attr_fan_mode
            self._attr_fan_mode = device_state.fan_mode
            _LOGGER.info(
                "%s: Optimistic window - fan_mode from cloud: %s (was %s)",
                self.name,
                device_state.fan_mode,
                old_fan,
            )

        if device_state.preset_mode is not None:
            old_preset = self._attr_preset_mode
            self._attr_preset_mode = device_state.preset_mode
            _LOGGER.info(
                "%s: Optimistic window - preset_mode from cloud: %s (was %s)",
                self.name,
                device_state.preset_mode,
                old_preset,
            )

    def _update_full_state(self, device_state: api.SabianaDeviceState) -> None:
        """Update all entity state from device state (past optimistic window)."""
        if device_state.hvac_mode is not None:
            try:
                self._attr_hvac_mode = HVACMode(device_state.hvac_mode)
            except ValueError:
                _LOGGER.warning("Unknown HVAC mode: %s", device_state.hvac_mode)

        if device_state.target_temperature is not None:
            self._attr_target_temperature = device_state.target_temperature

        if device_state.current_temperature is not None:
            self._attr_current_temperature = device_state.current_temperature

        if device_state.fan_mode is not None:
            old_fan = self._attr_fan_mode
            self._attr_fan_mode = device_state.fan_mode
            _LOGGER.debug(
                "%s: Updated fan_mode from %s to %s",
                self.name,
                old_fan,
                device_state.fan_mode,
            )

        if device_state.swing_mode is not None:
            self._attr_swing_mode = device_state.swing_mode

        if device_state.preset_mode is not None:
            old_preset = self._attr_preset_mode
            self._attr_preset_mode = device_state.preset_mode
            _LOGGER.debug(
                "%s: Updated preset_mode from %s to %s",
                self.name,
                old_preset,
                device_state.preset_mode,
            )

        _LOGGER.debug("Updated %s from coordinator: %s", self.name, device_state)

    async def async_will_remove_from_hass(self) -> None:
        """Handle entity being removed from Home Assistant."""
        await super().async_will_remove_from_hass()

        if self._coordinator_listener_unsub is not None:
            self._coordinator_listener_unsub()
            self._coordinator_listener_unsub = None

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        """Set the HVAC mode.

        Args:
            hvac_mode: The HVAC mode to set.

        """
        self._attr_hvac_mode = hvac_mode
        await self._async_execute_command()

    async def async_set_temperature(self, **kwargs: Any) -> None:  # noqa: ANN401
        """Set the target temperature.

        Args:
            **kwargs: Keyword arguments containing temperature data.

        """
        self._attr_target_temperature = kwargs.get(ATTR_TEMPERATURE)
        self.async_write_ha_state()

        if self.hvac_mode != HVACMode.OFF and self._attr_target_temperature is not None:
            await self._async_execute_command()

    async def async_set_fan_mode(self, fan_mode: str) -> None:
        """Set the fan mode.

        Args:
            fan_mode: The fan mode to set.

        """
        # CRITICAL: Set optimistic timestamp BEFORE updating state
        # This prevents coordinator from reverting the change
        self._last_command_time = time.monotonic()

        self._attr_fan_mode = fan_mode
        self.async_write_ha_state()

        if self.hvac_mode != HVACMode.OFF:
            await self._async_execute_command()

    async def async_set_swing_mode(self, swing_mode: str) -> None:
        """Set the swing mode.

        Args:
            swing_mode: The swing mode to set.

        """
        # CRITICAL: Set optimistic timestamp BEFORE updating state
        # This prevents coordinator from reverting the change
        self._last_command_time = time.monotonic()

        self._attr_swing_mode = swing_mode
        self.async_write_ha_state()

        if self.hvac_mode != HVACMode.OFF:
            await self._async_execute_command()

    async def async_set_preset_mode(self, preset_mode: str | None) -> None:
        """Set the preset mode.

        Args:
            preset_mode: The preset mode to set, or None to clear.

        """
        # CRITICAL: Set optimistic timestamp BEFORE updating state
        # This prevents coordinator from reverting the change
        self._last_command_time = time.monotonic()

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
