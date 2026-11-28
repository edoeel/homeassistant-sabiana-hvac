# Copyright (c) 2026 Edoardo Mistretta

"""Tests for the Sabiana HVAC climate entity."""

from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest
from homeassistant.components.climate import (
    ATTR_HVAC_MODE,
    PRESET_NONE,
    PRESET_SLEEP,
    ClimateEntityFeature,
    HVACAction,
    HVACMode,
)
from homeassistant.const import ATTR_TEMPERATURE
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError

from custom_components.sabiana_hvac import api, climate
from custom_components.sabiana_hvac.climate import (
    SabianaHvacClimateEntity,
    async_setup_entry,
)
from custom_components.sabiana_hvac.const import DOMAIN

if TYPE_CHECKING:
    from collections.abc import Iterator

from .frames import FLAG_NIGHT, FLAG_ON, FLAG_REQUEST, FLAG_TIMER, FLAGS_ON, build_frame

FLAG_AUTO = 1 << 2

# Carisma Fly 500D, on in heating with a thermostat request and night mode:
# fan auto, flap "Swing", T1 29.2, setpoints 24.5 / 26.0 / 22.0.
FRAME_500D_HEATING = build_frame(
    model="500D",
    mode=1,
    fan=4,
    flags=FLAGS_ON | FLAG_REQUEST | FLAG_AUTO | FLAG_NIGHT,
    flap=0x0401,
    t1=292,
    setpoint_summer=245,
    setpoint_winter=260,
    setpoint_auto=220,
    range_summer=0xB40A,  # cooling 11.0-28.0
)
# Same frame once the winter setpoint (word 8) is 21.5 °C.
FRAME_500D_HEATING_21_5 = FRAME_500D_HEATING[:28] + "00d7" + FRAME_500D_HEATING[32:]


def _cloud_device(**kwargs: object) -> api.SabianaDevice:
    """Build a device record as parsed from getDeviceForUserV2."""
    return api.parse_device(
        {
            "idDevice": "device1",
            "deviceName": "Test Device",
            "deviceStateModelType": "cvp",
            "lastData": FRAME_500D_HEATING,
            "connectionUp": True,
            "deviceStateFw": "1.23",
            **kwargs,
        }
    )


@pytest.fixture
def token_coordinator() -> Mock:
    """Create a mock token coordinator."""
    coordinator = Mock()
    coordinator.short_jwt.token = "short-token"  # noqa: S105
    coordinator.async_request_refresh = AsyncMock()
    coordinator.async_force_renew = AsyncMock(return_value="renewed-token")
    return coordinator


@pytest.fixture
def device_coordinator() -> Mock:
    """Create a mock device coordinator holding one 500D."""
    coordinator = Mock()
    coordinator.data = {"device1": _cloud_device()}
    coordinator.async_add_listener = Mock(return_value=Mock())
    coordinator.async_request_refresh = AsyncMock()
    coordinator.realtime_connected = True
    return coordinator


@pytest.fixture
def entity(
    token_coordinator: Mock, device_coordinator: Mock
) -> Iterator[SabianaHvacClimateEntity]:
    """Create the entity, with state writes mocked out."""
    entity = SabianaHvacClimateEntity(
        Mock(spec=httpx.AsyncClient),
        token_coordinator,
        device_coordinator,
        device_coordinator.data["device1"],
    )
    entity.async_write_ha_state = Mock()
    yield entity
    for task in entity._tasks:
        task.cancel()


@pytest.fixture
def send() -> Iterator[AsyncMock]:
    """Patch devices/cmd; it answers status 0."""
    with patch.object(
        api, "async_send_command", AsyncMock(return_value={"status": 0, "body": {}})
    ) as mock:
        yield mock


def _set_frame(device_coordinator: Mock, raw: str, **kwargs: object) -> None:
    device_coordinator.data = {"device1": _cloud_device(lastData=raw, **kwargs)}


def _sent(send: AsyncMock, index: int = 0) -> str:
    """Return the data of the index-th devices/cmd call."""
    return send.await_args_list[index].args[3]


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------


class TestAsyncSetupEntry:
    """Platform setup."""

    @pytest.mark.asyncio
    async def test_creates_entities_and_skips_rvu(
        self, token_coordinator: Mock, device_coordinator: Mock
    ) -> None:
        """Fancoils get an entity; RVU units never get fancoil commands."""
        hass = Mock()
        entry = Mock(entry_id="test_entry")
        rvu = api.SabianaDevice(id="rvu1", name="RVU", model_type="rvu")
        hass.data = {
            DOMAIN: {
                "test_entry": {
                    "session": Mock(),
                    "token_coordinator": token_coordinator,
                    "device_coordinator": device_coordinator,
                    "devices": [device_coordinator.data["device1"], rvu],
                }
            }
        }
        async_add_entities = Mock()
        await async_setup_entry(hass, entry, async_add_entities)
        entities = async_add_entities.call_args.args[0]
        assert [e.unique_id for e in entities] == ["device1"]
        assert isinstance(entities[0], SabianaHvacClimateEntity)


class TestDeviceInfo:
    """Device registry entry."""

    def test_device_info_from_record(self, entity: SabianaHvacClimateEntity) -> None:
        """Model, model code and firmware come from getDeviceForUserV2."""
        assert entity.name is None  # the entity takes the device name
        info = entity.device_info
        assert info is not None
        assert info["identifiers"] == {(DOMAIN, "device1")}
        assert info["name"] == "Test Device"
        assert info["manufacturer"] == "Sabiana"
        assert (info["model"], info["model_id"]) == ("Carisma Fly", "500D")
        assert (info["sw_version"], info["hw_version"]) == ("1.23", "0.43")


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


class TestAvailability:
    """Available follows connectionUp and the validity of lastData."""

    def test_available_when_online_and_valid(
        self, entity: SabianaHvacClimateEntity
    ) -> None:
        """Online with a valid frame: available."""
        assert entity.available is True

    @pytest.mark.parametrize(
        "kwargs", [{"connectionUp": False}, {"lastData": "999999"}]
    )
    def test_unavailable(
        self,
        entity: SabianaHvacClimateEntity,
        device_coordinator: Mock,
        kwargs: dict[str, Any],
    ) -> None:
        """Offline or DATA-ERROR: unavailable, as the app blocks control."""
        device_coordinator.data = {"device1": _cloud_device(**kwargs)}
        assert entity.available is False

    def test_unavailable_while_socket_is_down(
        self, entity: SabianaHvacClimateEntity, device_coordinator: Mock
    ) -> None:
        """App: with the socket down the cloud is offline, nothing is controllable."""
        device_coordinator.realtime_connected = False
        assert entity.available is False

    def test_unavailable_without_record(
        self, entity: SabianaHvacClimateEntity, device_coordinator: Mock
    ) -> None:
        """No record for the device: unavailable, no values."""
        device_coordinator.data = {}
        assert (entity.available, entity.hvac_mode) == (False, None)


class TestStateFromDevice:
    """Mapping of the decoded state onto the climate entity."""

    def test_heating_500d(self, entity: SabianaHvacClimateEntity) -> None:
        """Every attribute of a 500D in heating."""
        assert entity.hvac_mode == HVACMode.HEAT
        assert entity.hvac_action == HVACAction.HEATING
        assert (entity.target_temperature, entity.current_temperature) == (26.0, 29.2)
        assert (entity.min_temp, entity.max_temp) == (10.0, 30.0)
        assert entity.hvac_modes == [
            HVACMode.OFF,
            HVACMode.COOL,
            HVACMode.HEAT,
            HVACMode.AUTO,
            HVACMode.FAN_ONLY,
        ]
        assert (entity.fan_mode, entity.fan_modes) == (
            "auto",
            ["low", "medium", "high", "auto"],
        )
        assert entity.swing_mode == "Swing"
        assert entity.swing_modes == [
            "Stop swing",
            "Horizontal",
            "45 Degrees",
            "Vertical",
            "Swing",
        ]
        assert (entity.preset_mode, entity.preset_modes) == (
            PRESET_SLEEP,
            [PRESET_NONE, PRESET_SLEEP],
        )
        assert entity.supported_features == (
            ClimateEntityFeature.TURN_ON
            | ClimateEntityFeature.TURN_OFF
            | ClimateEntityFeature.FAN_MODE
            | ClimateEntityFeature.TARGET_TEMPERATURE
            | ClimateEntityFeature.SWING_MODE
            | ClimateEntityFeature.PRESET_MODE
        )

    def test_cool_mode_limits(
        self, entity: SabianaHvacClimateEntity, device_coordinator: Mock
    ) -> None:
        """Word 10 sets the limits in cooling."""
        cool = FRAME_500D_HEATING[:8] + "0400" + FRAME_500D_HEATING[12:]
        _set_frame(device_coordinator, cool)
        assert (entity.hvac_mode, entity.target_temperature) == (HVACMode.COOL, 24.5)
        assert (entity.min_temp, entity.max_temp) == (11.0, 28.0)

    def test_off(
        self, entity: SabianaHvacClimateEntity, device_coordinator: Mock
    ) -> None:
        """A unit switched off reports off."""
        _set_frame(device_coordinator, build_frame(flags=FLAGS_ON & ~FLAG_ON))
        assert (entity.hvac_mode, entity.hvac_action) == (HVACMode.OFF, HVACAction.OFF)

    def test_whisper_continuous_fan_without_flap(
        self, entity: SabianaHvacClimateEntity, device_coordinator: Mock
    ) -> None:
        """A Whisper (5020): 19A fan levels, no flap."""
        _set_frame(
            device_coordinator,
            build_frame(model="5020", fan=65),
            deviceStateModelType="evo",
        )
        assert entity.fan_mode == "5.5"
        assert entity.fan_modes is not None
        assert entity.fan_modes[:3] == ["auto", "1", "1.5"]
        assert entity.swing_modes is None
        assert not entity.supported_features & ClimateEntityFeature.SWING_MODE

    def test_meltemi(
        self, entity: SabianaHvacClimateEntity, device_coordinator: Mock
    ) -> None:
        """Meltemi: no cooling, two fan speeds, no night mode, simple flap."""
        _set_frame(
            device_coordinator,
            build_frame(model="5029", fan=1, flags=FLAGS_ON | FLAG_AUTO, flap=0x0001),
            deviceStateModelType="tmb",
        )
        assert HVACMode.COOL not in entity.hvac_modes
        assert HVACMode.AUTO in entity.hvac_modes  # max heating
        assert entity.fan_modes == ["low", "high"]
        assert entity.preset_modes is None
        assert entity.swing_modes == ["Stop swing", "Swing"]

    def test_fan_only_has_no_setpoint(
        self, entity: SabianaHvacClimateEntity, device_coordinator: Mock
    ) -> None:
        """No target temperature in fan only."""
        _set_frame(device_coordinator, build_frame(mode=3))
        assert (entity.hvac_mode, entity.target_temperature) == (
            HVACMode.FAN_ONLY,
            None,
        )
        assert not entity.supported_features & ClimateEntityFeature.TARGET_TEMPERATURE

    def test_eco_limited_mode(
        self, entity: SabianaHvacClimateEntity, device_coordinator: Mock
    ) -> None:
        """CFF ECO without DIP: only on/off and fan."""
        _set_frame(
            device_coordinator,
            build_frame(model="5021", mode=1),
            deviceStateModelType="eco",
        )
        assert entity.hvac_modes == [HVACMode.OFF, HVACMode.HEAT]
        assert not entity.supported_features & ClimateEntityFeature.TARGET_TEMPERATURE
        assert not entity.supported_features & ClimateEntityFeature.PRESET_MODE


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


class TestCommands:
    """Each action sends the full 2304 block built from the current state."""

    @pytest.mark.asyncio
    async def test_set_temperature(
        self,
        entity: SabianaHvacClimateEntity,
        send: AsyncMock,
        token_coordinator: Mock,
    ) -> None:
        """The setpoint goes in register 2; flap and night are kept."""
        await entity.async_set_temperature(**{ATTR_TEMPERATURE: 21.5})
        token_coordinator.async_request_refresh.assert_awaited()
        assert send.await_args.args[1:3] == ("short-token", "device1")
        assert _sent(send) == "040100D70401FFFF0002"
        assert entity.target_temperature == 21.5  # noqa: PLR2004 (pending value)

    @pytest.mark.asyncio
    async def test_set_temperature_keeps_timer(
        self,
        entity: SabianaHvacClimateEntity,
        device_coordinator: Mock,
        send: AsyncMock,
    ) -> None:
        """An active timer stays active (bit 0 of register 5)."""
        _set_frame(device_coordinator, build_frame(flags=FLAGS_ON | FLAG_TIMER))
        await entity.async_set_temperature(**{ATTR_TEMPERATURE: 22})
        assert _sent(send).endswith("0001")

    @pytest.mark.asyncio
    async def test_set_temperature_with_mode(
        self, entity: SabianaHvacClimateEntity, send: AsyncMock
    ) -> None:
        """Mode and temperature in one call: one command."""
        await entity.async_set_temperature(
            **{ATTR_TEMPERATURE: 23, ATTR_HVAC_MODE: HVACMode.COOL}
        )
        assert send.await_count == 1
        assert _sent(send) == "040000E60401FFFF0002"

    @pytest.mark.asyncio
    async def test_set_temperature_in_fan_only_is_refused(
        self,
        entity: SabianaHvacClimateEntity,
        device_coordinator: Mock,
        send: AsyncMock,
    ) -> None:
        """Fan only has no setpoint."""
        _set_frame(device_coordinator, build_frame(mode=3))
        with pytest.raises(ServiceValidationError):
            await entity.async_set_temperature(**{ATTR_TEMPERATURE: 22})
        send.assert_not_awaited()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("hvac_mode", "expected"),
        [
            (HVACMode.COOL, "040000F50401FFFF0002"),  # summer setpoint 24.5
            (HVACMode.AUTO, "040200DC0401FFFF0002"),  # auto setpoint 22.0
            (HVACMode.FAN_ONLY, "040300000401FFFF0002"),  # setpoint 0
            (HVACMode.OFF, "040401040401FFFF0002"),  # mode 4, values kept
        ],
    )
    async def test_set_hvac_mode(
        self,
        entity: SabianaHvacClimateEntity,
        send: AsyncMock,
        hvac_mode: HVACMode,
        expected: str,
    ) -> None:
        """A mode change loads the setpoint stored for that mode."""
        await entity.async_set_hvac_mode(hvac_mode)
        assert _sent(send) == expected
        assert entity.hvac_mode == hvac_mode

    @pytest.mark.asyncio
    async def test_turn_on_keeps_the_mode(
        self,
        entity: SabianaHvacClimateEntity,
        device_coordinator: Mock,
        send: AsyncMock,
    ) -> None:
        """Turning on restores the stored mode (cooling here), not fan only."""
        _set_frame(device_coordinator, build_frame(mode=0, flags=FLAGS_ON & ~FLAG_ON))
        await entity.async_turn_on()
        assert _sent(send) == "040000F0FF00FFFF0000"
        assert entity.hvac_mode == HVACMode.COOL

    @pytest.mark.asyncio
    async def test_turn_off(
        self, entity: SabianaHvacClimateEntity, send: AsyncMock
    ) -> None:
        """Off is mode 4 with the current fan."""
        await entity.async_turn_off()
        assert _sent(send).startswith("0404")
        assert entity.hvac_mode == HVACMode.OFF

    @pytest.mark.asyncio
    async def test_turn_off_keeps_the_flap_set_from_the_app(
        self,
        entity: SabianaHvacClimateEntity,
        device_coordinator: Mock,
        send: AsyncMock,
    ) -> None:
        """Regression: the old integration reopened the flap when turning off.

        HA had set "Vertical" (full open), then the app set "Stop swing"
        (position 0), which the old code could not represent: turning off
        from HA sent 0301 and left the flap open. The off command must carry
        the position the unit reports, as the app does.
        """
        await entity.async_set_swing_mode("Vertical")
        assert _sent(send)[8:12] == "0301"
        full_open = FRAME_500D_HEATING[:16] + "0301" + FRAME_500D_HEATING[20:]
        _set_frame(device_coordinator, full_open)
        entity._handle_coordinator_update()  # confirmed
        stop_swing = FRAME_500D_HEATING[:16] + "0001" + FRAME_500D_HEATING[20:]
        _set_frame(device_coordinator, stop_swing)  # changed from the app
        entity._handle_coordinator_update()
        assert entity.swing_mode == "Stop swing"

        entity._last_send = -climate.COMMAND_THROTTLE  # later, outside the throttle
        await entity.async_turn_off()
        assert _sent(send, 1) == "040401040001FFFF0002"

    @pytest.mark.asyncio
    async def test_remote_off_blocks_turning_on(
        self,
        entity: SabianaHvacClimateEntity,
        device_coordinator: Mock,
        send: AsyncMock,
    ) -> None:
        """With the remote on/off active the app forbids turning on."""
        _set_frame(device_coordinator, build_frame(flags=FLAG_ON))  # bit 8 = 0
        with pytest.raises(ServiceValidationError, match="remote control"):
            await entity.async_turn_on()
        with pytest.raises(ServiceValidationError, match="remote control"):
            await entity.async_set_hvac_mode(HVACMode.HEAT)
        send.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_set_fan_mode_on_continuous_scale(
        self,
        entity: SabianaHvacClimateEntity,
        device_coordinator: Mock,
        send: AsyncMock,
    ) -> None:
        """19A: level 5.5 is fan value 65 (0x41); names of other scales fail."""
        _set_frame(
            device_coordinator, build_frame(model="5020"), deviceStateModelType="evo"
        )
        await entity.async_set_fan_mode("5.5")
        assert _sent(send) == "410100C8FF00FFFF0000"
        with pytest.raises(ServiceValidationError):
            await entity.async_set_fan_mode("medium")

    @pytest.mark.asyncio
    async def test_set_swing_mode(
        self, entity: SabianaHvacClimateEntity, send: AsyncMock
    ) -> None:
        """Stop swing is flap position 0."""
        await entity.async_set_swing_mode("Stop swing")
        assert _sent(send) == "040101040001FFFF0002"

    @pytest.mark.asyncio
    async def test_unit_without_flap(
        self,
        entity: SabianaHvacClimateEntity,
        device_coordinator: Mock,
        send: AsyncMock,
    ) -> None:
        """Units without flap send FF00 and refuse swing modes."""
        _set_frame(
            device_coordinator, build_frame(model="5020"), deviceStateModelType="evo"
        )
        with pytest.raises(ServiceValidationError):
            await entity.async_set_swing_mode("Swing")
        await entity.async_set_temperature(**{ATTR_TEMPERATURE: 21})
        assert _sent(send)[8:12] == "FF00"

    @pytest.mark.asyncio
    async def test_set_preset_mode(
        self,
        entity: SabianaHvacClimateEntity,
        device_coordinator: Mock,
        send: AsyncMock,
    ) -> None:
        """Night mode is bit 1 of register 5, and only changes when on."""
        await entity.async_set_preset_mode(PRESET_NONE)
        assert _sent(send).endswith("0000")

        _set_frame(device_coordinator, build_frame(flags=FLAGS_ON & ~FLAG_ON))
        entity._pending = None
        with pytest.raises(ServiceValidationError, match="Turn"):
            await entity.async_set_preset_mode(PRESET_SLEEP)

    @pytest.mark.asyncio
    async def test_setpoint_and_fan_need_the_unit_on(
        self,
        entity: SabianaHvacClimateEntity,
        device_coordinator: Mock,
        send: AsyncMock,
    ) -> None:
        """App: while off only on/off and the flap can be used."""
        _set_frame(
            device_coordinator, build_frame(flap=0x0401, flags=FLAGS_ON & ~FLAG_ON)
        )
        with pytest.raises(ServiceValidationError, match="setpoint"):
            await entity.async_set_temperature(**{ATTR_TEMPERATURE: 22})
        with pytest.raises(ServiceValidationError, match="fan speed"):
            await entity.async_set_fan_mode("high")
        send.assert_not_awaited()

        await entity.async_set_swing_mode("Stop swing")  # the flap works when off
        assert _sent(send) == "040400C80001FFFF0000"

    @pytest.mark.asyncio
    async def test_setpoint_with_turn_on_is_allowed_when_off(
        self,
        entity: SabianaHvacClimateEntity,
        device_coordinator: Mock,
        send: AsyncMock,
    ) -> None:
        """A call that also turns the unit on may set the setpoint."""
        _set_frame(device_coordinator, build_frame(flags=FLAGS_ON & ~FLAG_ON))
        await entity.async_set_temperature(
            **{ATTR_TEMPERATURE: 22, ATTR_HVAC_MODE: HVACMode.HEAT}
        )
        assert _sent(send) == "040100DCFF00FFFF0000"

    @pytest.mark.asyncio
    async def test_timer_bit_is_read_when_sending(
        self,
        entity: SabianaHvacClimateEntity,
        device_coordinator: Mock,
        send: AsyncMock,
    ) -> None:
        """A frame arriving during the throttle updates the timer bit sent."""
        await entity.async_set_temperature(**{ATTR_TEMPERATURE: 21})
        await entity.async_set_temperature(**{ATTR_TEMPERATURE: 21.5})  # trailing
        timer_on = FRAME_500D_HEATING[:12] + "11c7" + FRAME_500D_HEATING[16:]
        _set_frame(device_coordinator, timer_on)
        assert entity._trailing_task is not None
        with patch.object(climate.asyncio, "sleep", AsyncMock()):
            await entity._trailing_task
        assert _sent(send, 1) == "040100D70401FFFF0003"

    @pytest.mark.asyncio
    async def test_unchanged_values_send_nothing(
        self, entity: SabianaHvacClimateEntity, send: AsyncMock
    ) -> None:
        """Like the app, nothing is sent when nothing changes."""
        await entity.async_set_hvac_mode(HVACMode.HEAT)
        await entity.async_set_temperature(**{ATTR_TEMPERATURE: 26.0})
        send.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_offline_device_refuses_commands(
        self,
        entity: SabianaHvacClimateEntity,
        device_coordinator: Mock,
        send: AsyncMock,
    ) -> None:
        """Offline units cannot be controlled."""
        device_coordinator.data = {"device1": _cloud_device(connectionUp=False)}
        with pytest.raises(HomeAssistantError, match="offline"):
            await entity.async_turn_off()
        send.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_socket_down_refuses_commands(
        self,
        entity: SabianaHvacClimateEntity,
        device_coordinator: Mock,
        send: AsyncMock,
    ) -> None:
        """No REST fallback: commands wait for the socket, like the app."""
        device_coordinator.realtime_connected = False
        with pytest.raises(HomeAssistantError, match="cloud is offline"):
            await entity.async_set_temperature(**{ATTR_TEMPERATURE: 21})
        send.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_send_error_clears_pending(
        self, entity: SabianaHvacClimateEntity, send: AsyncMock
    ) -> None:
        """A rejected command raises and shows the device state again."""
        send.side_effect = api.SabianaApiClientError("boom")
        with pytest.raises(HomeAssistantError, match="boom"):
            await entity.async_set_temperature(**{ATTR_TEMPERATURE: 21})
        assert entity._pending is None
        assert entity.target_temperature == 26.0  # noqa: PLR2004

    @pytest.mark.asyncio
    async def test_auth_error_renews_and_retries_once(
        self,
        entity: SabianaHvacClimateEntity,
        send: AsyncMock,
        token_coordinator: Mock,
    ) -> None:
        """A rejected token is renewed and the command sent again."""
        send.side_effect = [api.SabianaApiAuthError("expired"), {"status": 0}]
        await entity.async_set_temperature(**{ATTR_TEMPERATURE: 21})
        token_coordinator.async_force_renew.assert_awaited_once()
        assert send.await_args_list[1].args[1] == "renewed-token"

    @pytest.mark.asyncio
    async def test_rotated_token_is_stored(
        self,
        entity: SabianaHvacClimateEntity,
        send: AsyncMock,
        token_coordinator: Mock,
    ) -> None:
        """A token in the cmd response is the new long JWT."""
        send.return_value = {"status": 0, "token": "a.rotated-long.jwt"}
        await entity.async_set_temperature(**{ATTR_TEMPERATURE: 21})
        token_coordinator.store_rotated_long_jwt.assert_called_once_with(
            "a.rotated-long.jwt"
        )


# ---------------------------------------------------------------------------
# Confirmation and throttling
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("send")
class TestConfirmation:
    """Pending values are kept until a matching frame, or a timeout."""

    @pytest.mark.asyncio
    async def test_matching_frame_confirms(
        self, entity: SabianaHvacClimateEntity, device_coordinator: Mock
    ) -> None:
        """A frame showing the new setpoint ends the pending state."""
        await entity.async_set_temperature(**{ATTR_TEMPERATURE: 21.5})

        entity._handle_coordinator_update()  # an older frame: still pending
        assert entity._pending is not None
        assert entity.target_temperature == 21.5  # noqa: PLR2004

        _set_frame(device_coordinator, FRAME_500D_HEATING_21_5)
        entity._handle_coordinator_update()
        assert entity._pending is None
        assert entity.target_temperature == 21.5  # noqa: PLR2004

    @pytest.mark.asyncio
    async def test_timeout_reverts(
        self, entity: SabianaHvacClimateEntity, device_coordinator: Mock
    ) -> None:
        """Without confirmation the device state is shown again."""
        with patch.object(climate.asyncio, "sleep", AsyncMock()) as sleep:
            await entity.async_set_temperature(**{ATTR_TEMPERATURE: 21.5})
            for task in list(entity._tasks):
                await task
        sleep.assert_awaited_with(climate.COMMAND_CONFIRM_TIMEOUT)
        device_coordinator.async_request_refresh.assert_not_awaited()
        assert entity._pending is None
        assert entity.target_temperature == 26.0  # noqa: PLR2004


class TestThrottle:
    """At most one command every 1.5 s; the last values win."""

    @pytest.mark.asyncio
    async def test_leading_and_trailing(
        self, entity: SabianaHvacClimateEntity, send: AsyncMock
    ) -> None:
        """First change sent at once, later ones merged into one send."""
        await entity.async_set_temperature(**{ATTR_TEMPERATURE: 21})
        await entity.async_set_temperature(**{ATTR_TEMPERATURE: 21.5})
        await entity.async_set_fan_mode("high")
        assert send.await_count == 1
        assert entity._trailing_task is not None

        with patch.object(climate.asyncio, "sleep", AsyncMock()):
            await entity._trailing_task
        assert send.await_count == 2  # noqa: PLR2004
        assert _sent(send, 1) == "030100D70401FFFF0002"
