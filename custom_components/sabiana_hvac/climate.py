# Copyright (c) 2026 Edoardo Mistretta

"""Climate entities for Sabiana fancoils.

Each entity shows the state decoded from the device's lastData. Commands work
like the app's single fancoil page (doSendCmd):

- every change sends the full block (devices/cmd, start 2304) built from the
  current state with one value changed, so timer and night bits are kept;
- changes are throttled to one command every 1.5 s (leading and trailing);
- the sent values are shown until a "data" frame shows them applied; without
  one the entity goes back to the device state after a timeout.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import replace
from typing import TYPE_CHECKING, Any

import httpx
from homeassistant.components.climate import (
    ATTR_HVAC_MODE,
    PRESET_NONE,
    PRESET_SLEEP,
    ClimateEntity,
    ClimateEntityFeature,
    HVACAction,
    HVACMode,
)
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import UpdateFailed

from . import api
from .const import (
    DOMAIN,
    FLAP_POSITION_TO_SWING_MODE,
    FLAP_SIMPLE_POSITIONS,
    SWING_MODE_TO_FLAP_POSITION,
)
from .models import MODE_AUTO, MODE_COOL, MODE_FAN_ONLY, MODE_HEAT
from .protocol import FancoilCommand, fan_mode_name, fan_scale

if TYPE_CHECKING:
    from collections.abc import Coroutine

    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

    from .coordinator import SabianaDeviceCoordinator, SabianaTokenCoordinator
    from .models import SabianaDevice, SabianaDeviceState

_LOGGER = logging.getLogger(__name__)

# App: throttle(1500, {leading: true, trailing: true}) on the Sabiana brand
COMMAND_THROTTLE = 1.5
# App: 3.9 s for any "data" event; here a matching frame is required, so
# allow a little more.
COMMAND_CONFIRM_TIMEOUT = 5.0

MODE_TO_HVAC_MODE = {
    MODE_COOL: HVACMode.COOL,
    MODE_HEAT: HVACMode.HEAT,
    MODE_AUTO: HVACMode.AUTO,
    MODE_FAN_ONLY: HVACMode.FAN_ONLY,
}
HVAC_MODE_TO_MODE = {hvac: mode for mode, hvac in MODE_TO_HVAC_MODE.items()}

# Message of the app (translation key cloudwm.CantOnRemoteOff)
MSG_REMOTE_OFF = "The device is turned off by the remote control, you cannot turn it on"


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up climate entities for Sabiana HVAC devices."""
    entry_data = hass.data[DOMAIN][entry.entry_id]
    token_coordinator = entry_data["token_coordinator"]
    device_coordinator = entry_data["device_coordinator"]

    entities = []
    for device in entry_data["devices"]:
        if device.is_rvu:
            # RVU units use another register map and are not supported yet:
            # never send them fancoil commands.
            _LOGGER.warning(
                "Device %s (%s) is an RVU heat recovery unit, not supported yet",
                device.name,
                device.id,
            )
            continue
        entities.append(
            SabianaHvacClimateEntity(
                entry_data["session"],
                token_coordinator,
                device_coordinator,
                device,
            )
        )
    async_add_entities(entities)


class SabianaHvacClimateEntity(ClimateEntity):
    """Climate entity for a Sabiana fancoil."""

    _attr_temperature_unit = UnitOfTemperature.CELSIUS
    _attr_target_temperature_step = 0.5
    _attr_has_entity_name = True
    # Main feature of the device: the entity takes the device name.
    _attr_name = None
    _attr_should_poll = False

    def __init__(
        self,
        session: httpx.AsyncClient,
        token_coordinator: SabianaTokenCoordinator,
        device_coordinator: SabianaDeviceCoordinator,
        device: SabianaDevice,
    ) -> None:
        """Initialize the entity.

        Args:
            session: HTTP client session for API calls.
            token_coordinator: Token coordinator for managing JWT tokens.
            device_coordinator: Coordinator holding the device records.
            device: The device record found at setup.

        """
        self._session = session
        self._token_coordinator = token_coordinator
        self._device_coordinator = device_coordinator
        self._device = device
        self._attr_unique_id = device.id
        self._attr_device_info = self._build_device_info(device)

        self._pending: FancoilCommand | None = None
        self._last_send = -COMMAND_THROTTLE
        self._tasks: set[asyncio.Task[None]] = set()
        self._trailing_task: asyncio.Task[None] | None = None
        self._unsub_coordinator: Any = None

    @staticmethod
    def _build_device_info(device: SabianaDevice) -> DeviceInfo:
        """Return the device registry entry, from the getDeviceForUserV2 record."""
        info = DeviceInfo(
            identifiers={(DOMAIN, device.id)},
            manufacturer="Sabiana",
            name=device.name,
            serial_number=device.id,
        )
        if device.state is not None:
            info["model"] = device.state.commercial_name
            info["model_id"] = device.state.controller_model
            info["hw_version"] = device.state.fw_release
        if device.wifi_fw:
            info["sw_version"] = device.wifi_fw
        return info

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------

    @property
    def _cloud_device(self) -> SabianaDevice | None:
        """Return the latest record of this device from the coordinator."""
        if not self._device_coordinator.data:
            return None
        return self._device_coordinator.data.get(self._device.id)

    @property
    def _state(self) -> SabianaDeviceState | None:
        device = self._cloud_device
        return device.state if device is not None else None

    @property
    def _view(self) -> FancoilCommand | None:
        """Return the values to show: the pending command, else the device."""
        if self._pending is not None:
            return self._pending
        state = self._state
        return FancoilCommand.from_state(state) if state is not None else None

    @property
    def available(self) -> bool:
        """Return whether the device can be controlled.

        As in the app: the Socket.IO channel is up (isCloudOnLine), the cloud
        reports the device connected (connectionUp) and its last frame is
        valid (no DATA-ERROR).
        """
        device = self._cloud_device
        return (
            self._device_coordinator.realtime_connected
            and device is not None
            and device.controllable
        )

    @property
    def supported_features(self) -> ClimateEntityFeature:
        """Return the features of the unit, from its profile and state."""
        features = (
            ClimateEntityFeature.TURN_ON
            | ClimateEntityFeature.TURN_OFF
            | ClimateEntityFeature.FAN_MODE
        )
        state, view = self._state, self._view
        if state is None or view is None:
            return features
        if not state.eco_limited_mode and view.mode != MODE_FAN_ONLY:
            features |= ClimateEntityFeature.TARGET_TEMPERATURE
        if state.flap_present:
            features |= ClimateEntityFeature.SWING_MODE
        if state.night_mode_available and not state.eco_limited_mode:
            features |= ClimateEntityFeature.PRESET_MODE
        return features

    @property
    def hvac_modes(self) -> list[HVACMode]:
        """Return the modes the unit accepts."""
        state = self._state
        if state is None:
            return [HVACMode.OFF]
        if state.eco_limited_mode:
            # CFF ECO without DIP: only on/off and fan, the mode is fixed.
            current = MODE_TO_HVAC_MODE.get(state.mode)
            return [HVACMode.OFF] + ([current] if current else [])
        modes = [HVACMode.OFF]
        if not state.is_door_curtain:  # the Meltemi does not cool
            modes.append(HVACMode.COOL)
        modes.append(HVACMode.HEAT)
        if state.auto_mode_available:  # per unit, bit 2 of word 4
            modes.append(HVACMode.AUTO)  # "max heating" on the Meltemi
        modes.append(HVACMode.FAN_ONLY)
        return modes

    @property
    def hvac_mode(self) -> HVACMode | None:
        """Return the current mode, off when the unit is off."""
        view = self._view
        if view is None:
            return None
        if not view.on:
            return HVACMode.OFF
        return MODE_TO_HVAC_MODE.get(view.mode)

    @property
    def hvac_action(self) -> HVACAction | None:
        """Return what the unit is doing, from the app's mode icon logic."""
        state = self._state
        if state is None or state.hvac_action is None:
            return None
        return HVACAction(state.hvac_action)

    @property
    def current_temperature(self) -> float | None:
        """Return the room temperature (T1)."""
        state = self._state
        return state.t1 if state is not None else None

    @property
    def target_temperature(self) -> float | None:
        """Return the setpoint of the current mode (none in fan only)."""
        view = self._view
        if view is None or view.mode == MODE_FAN_ONLY:
            return None
        return view.setpoint

    @property
    def min_temp(self) -> float:
        """Return the lowest setpoint of the current mode."""
        return self._setpoint_range()[0]

    @property
    def max_temp(self) -> float:
        """Return the highest setpoint of the current mode."""
        return self._setpoint_range()[1]

    def _setpoint_range(self) -> tuple[float, float]:
        state, view = self._state, self._view
        if state is None or view is None:
            return (10.0, 30.0)
        return state.setpoint_range(view.mode)

    @property
    def fan_modes(self) -> list[str] | None:
        """Return the fan speeds of the unit's scale."""
        state = self._state
        if state is None:
            return None
        return [name for name, _ in fan_scale(state)]

    @property
    def fan_mode(self) -> str | None:
        """Return the current fan speed."""
        state, view = self._state, self._view
        if state is None or view is None:
            return None
        return fan_mode_name(state, view.fan)

    @property
    def swing_modes(self) -> list[str] | None:
        """Return the flap positions of the unit."""
        state = self._state
        if state is None or not state.flap_present:
            return None
        positions = (
            FLAP_SIMPLE_POSITIONS
            if state.flap_simple_mode
            else tuple(FLAP_POSITION_TO_SWING_MODE)
        )
        return [FLAP_POSITION_TO_SWING_MODE[p] for p in positions]

    @property
    def swing_mode(self) -> str | None:
        """Return the current flap position."""
        view = self._view
        if view is None or view.flap_position is None:
            return None
        return FLAP_POSITION_TO_SWING_MODE.get(view.flap_position)

    @property
    def preset_modes(self) -> list[str] | None:
        """Return the presets: night mode (sleep) where the model has it."""
        state = self._state
        if state is None or not state.night_mode_available:
            return None
        return [PRESET_NONE, PRESET_SLEEP]

    @property
    def preset_mode(self) -> str | None:
        """Return sleep when the night mode is on."""
        view = self._view
        if view is None:
            return None
        return PRESET_SLEEP if view.night_on else PRESET_NONE

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def async_added_to_hass(self) -> None:
        """Subscribe to device updates."""
        await super().async_added_to_hass()
        self._unsub_coordinator = self._device_coordinator.async_add_listener(
            self._handle_coordinator_update
        )

    async def async_will_remove_from_hass(self) -> None:
        """Unsubscribe and stop pending work."""
        await super().async_will_remove_from_hass()
        if self._unsub_coordinator is not None:
            self._unsub_coordinator()
            self._unsub_coordinator = None
        for task in self._tasks:
            task.cancel()
        self._tasks.clear()

    def _handle_coordinator_update(self) -> None:
        """Handle a new device record (REST read or Socket.IO event)."""
        state = self._state
        if self._pending is not None and state is not None:
            if self._pending.is_applied(state):
                _LOGGER.debug("%s confirmed the command", self._device.name)
                self._pending = None
            else:
                _LOGGER.debug(
                    "%s: frame does not match the pending command yet",
                    self._device.name,
                )
        self.async_write_ha_state()

    # ------------------------------------------------------------------
    # Services
    # ------------------------------------------------------------------

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        """Set the HVAC mode (off turns the unit off)."""
        state, view = self._require_state()
        await self._async_apply(self._command_for_hvac_mode(state, view, hvac_mode))

    async def async_turn_on(self) -> None:
        """Turn the unit on in its current mode, as the app does."""
        state, view = self._require_state()
        self._check_can_turn_on(state)
        await self._async_apply(replace(view, on=True))

    async def async_turn_off(self) -> None:
        """Turn the unit off (mode 4 in the command)."""
        _, view = self._require_state()
        await self._async_apply(replace(view, on=False))

    async def async_set_temperature(self, **kwargs: Any) -> None:  # noqa: ANN401
        """Set the setpoint of the current (or given) mode."""
        state, view = self._require_state()
        command = view
        if (hvac_mode := kwargs.get(ATTR_HVAC_MODE)) is not None:
            command = self._command_for_hvac_mode(state, view, hvac_mode)
        if (temperature := kwargs.get(ATTR_TEMPERATURE)) is not None:
            self._check_on(command, "the setpoint")
            if state.eco_limited_mode or command.mode == MODE_FAN_ONLY:
                msg = f"{self._device.name} has no setpoint in the current mode"
                raise ServiceValidationError(msg)
            command = replace(command, setpoint=float(temperature))
        await self._async_apply(command)

    async def async_set_fan_mode(self, fan_mode: str) -> None:
        """Set the fan speed, on the unit's own scale."""
        state, view = self._require_state()
        values = dict(fan_scale(state))
        if fan_mode not in values:
            msg = f"Fan mode {fan_mode} is not supported by {self._device.name}"
            raise ServiceValidationError(msg)
        self._check_on(view, "the fan speed")
        await self._async_apply(replace(view, fan=values[fan_mode]))

    async def async_set_swing_mode(self, swing_mode: str) -> None:
        """Set the flap position."""
        state, view = self._require_state()
        if not state.flap_present or swing_mode not in (self.swing_modes or []):
            msg = f"Swing mode {swing_mode} is not supported by {self._device.name}"
            raise ServiceValidationError(msg)
        # App: the flap control is hidden while the unit is off. The firmware
        # would store a flap sent with an off command and move the flap.
        self._check_on(view, "the flap")
        position = SWING_MODE_TO_FLAP_POSITION[swing_mode]
        await self._async_apply(replace(view, flap_position=position))

    async def async_set_preset_mode(self, preset_mode: str) -> None:
        """Turn the night mode on (sleep) or off (none)."""
        state, view = self._require_state()
        if not state.night_mode_available or preset_mode not in (
            PRESET_NONE,
            PRESET_SLEEP,
        ):
            msg = f"Preset {preset_mode} is not supported by {self._device.name}"
            raise ServiceValidationError(msg)
        # App: onToggleNight only acts when the unit is on.
        self._check_on(view, "the night mode")
        await self._async_apply(replace(view, night_on=preset_mode == PRESET_SLEEP))

    def _command_for_hvac_mode(
        self, state: SabianaDeviceState, view: FancoilCommand, hvac_mode: HVACMode
    ) -> FancoilCommand:
        if hvac_mode == HVACMode.OFF:
            return replace(view, on=False)
        if hvac_mode not in self.hvac_modes:
            msg = f"HVAC mode {hvac_mode} is not supported by {self._device.name}"
            raise ServiceValidationError(msg)
        self._check_can_turn_on(state)
        mode = HVAC_MODE_TO_MODE[hvac_mode]
        if mode == view.mode:
            return replace(view, on=True)
        return view.with_mode(state, mode)

    def _require_state(self) -> tuple[SabianaDeviceState, FancoilCommand]:
        """Return state and shown values, or fail if the unit cannot be controlled."""
        if not self._device_coordinator.realtime_connected:
            msg = "The Sabiana cloud is offline (WebSocket disconnected)"
            raise HomeAssistantError(msg)
        device = self._cloud_device
        view = self._view
        if device is None or not device.controllable or view is None:
            msg = f"{self._device.name} is offline or its data is not valid"
            raise HomeAssistantError(msg)
        assert device.state is not None  # noqa: S101 (controllable implies it)
        return device.state, view

    def _check_on(self, command: FancoilCommand, what: str) -> None:
        """Refuse a change the app only allows while the unit is on.

        App: while off only the on/off control can be used; setpoint, fan,
        night mode and flap need the unit on.
        """
        if not command.on:
            msg = f"Turn {self._device.name} on to change {what}"
            raise ServiceValidationError(msg)

    def _check_can_turn_on(self, state: SabianaDeviceState) -> None:
        if state.remote_on_off:
            msg = f"{self._device.name}: {MSG_REMOTE_OFF}"
            raise ServiceValidationError(msg)

    # ------------------------------------------------------------------
    # Sending
    # ------------------------------------------------------------------

    async def _async_apply(self, command: FancoilCommand) -> None:
        """Show a command as pending and send it (throttled)."""
        if command == self._view:
            return  # nothing changes, the app sends nothing either
        self._pending = command
        self.async_write_ha_state()

        if self._trailing_task is not None and not self._trailing_task.done():
            return  # the scheduled send will carry these values
        wait = self._last_send + COMMAND_THROTTLE - time.monotonic()
        if wait > 0:
            self._trailing_task = self._create_task(self._async_send_later(wait))
            return
        await self._async_send_pending()

    async def _async_send_later(self, delay: float) -> None:
        await asyncio.sleep(delay)
        try:
            await self._async_send_pending()
        except HomeAssistantError as err:
            _LOGGER.warning("%s", err)

    async def _async_send_pending(self) -> None:
        command = self._pending
        if command is None:
            return
        self._last_send = time.monotonic()
        # App: the timer bit is read from the unit when the command is sent
        # (getOptionsForCmd in doSendCmd), so a newer frame wins.
        state = self._state
        to_send = (
            command if state is None else replace(command, timer_on=state.timer_on)
        )
        try:
            response = await self._async_post(to_send.to_hex())
        except (api.SabianaApiClientError, httpx.RequestError, UpdateFailed) as err:
            if self._pending is command:
                self._pending = None
                self.async_write_ha_state()
            msg = f"Could not send the command to {self._device.name}: {err}"
            raise HomeAssistantError(msg) from err

        if rotated := api.extract_rotated_token(response):
            self._token_coordinator.store_rotated_long_jwt(rotated)
        if self._pending is command:
            self._create_task(self._async_confirm(command))

    async def _async_post(self, data: str) -> dict[str, Any]:
        """POST devices/cmd with a fresh token, retrying once on auth errors."""
        await self._token_coordinator.async_request_refresh()
        try:
            return await api.async_send_command(
                self._session,
                self._token_coordinator.short_jwt.token,
                self._device.id,
                data,
            )
        except api.SabianaApiAuthError:
            _LOGGER.debug(
                "Auth error for %s, renewing the token and retrying once",
                self._device.name,
            )
            token = await self._token_coordinator.async_force_renew()
            return await api.async_send_command(
                self._session, token, self._device.id, data
            )

    async def _async_confirm(self, command: FancoilCommand) -> None:
        """Go back to the device state if no frame confirms the command."""
        await asyncio.sleep(COMMAND_CONFIRM_TIMEOUT)
        if self._pending is not command:
            return  # confirmed, or replaced by a newer command
        _LOGGER.warning(
            "%s did not confirm the command within %.0fs, showing its state again",
            self._device.name,
            COMMAND_CONFIRM_TIMEOUT,
        )
        self._pending = None
        self.async_write_ha_state()

    def _create_task(self, coro: Coroutine[Any, Any, None]) -> asyncio.Task[None]:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task
