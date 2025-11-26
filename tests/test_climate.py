from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest
from homeassistant.components.climate import HVACMode
from homeassistant.components.climate.const import (
    FAN_AUTO,
    FAN_HIGH,
    FAN_LOW,
    FAN_MEDIUM,
    PRESET_NONE,
    PRESET_SLEEP,
)
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature

from custom_components.sabiana_hvac import api
from custom_components.sabiana_hvac.api import SabianaApiAuthError, SabianaApiClientError
from custom_components.sabiana_hvac.climate import (
    SabianaHvacClimateEntity,
    async_setup_entry,
)


@pytest.fixture
def mock_hass():
    hass = Mock()
    hass.data = {}
    return hass


@pytest.fixture
def mock_session():
    return Mock(spec=httpx.AsyncClient)


@pytest.fixture
def mock_coordinator():
    coordinator = Mock()
    coordinator.short_jwt = Mock()
    coordinator.short_jwt.token = "test_jwt_token"
    coordinator.async_add_listener = Mock(return_value=Mock())
    return coordinator


@pytest.fixture
def mock_device():
    device = api.SabianaDevice(id="device1", name="Test Device")
    return device


@pytest.fixture
def entity(mock_session, mock_coordinator, mock_device):
    return SabianaHvacClimateEntity(mock_session, mock_coordinator, mock_device)


class TestAsyncSetupEntry:
    @pytest.mark.asyncio
    async def test_async_setup_entry_creates_entities_for_all_devices(
        self, mock_hass, mock_session, mock_coordinator, mock_device
    ):
        entry = Mock()
        entry.entry_id = "test_entry"
        mock_hass.data["sabiana_hvac"] = {
            "test_entry": {
                "session": mock_session,
                "coordinator": mock_coordinator,
                "devices": [mock_device],
            }
        }
        async_add_entities = AsyncMock()
        await async_setup_entry(mock_hass, entry, async_add_entities)
        async_add_entities.assert_called_once()
        assert len(async_add_entities.call_args[0][0]) == 1
        assert isinstance(async_add_entities.call_args[0][0][0], SabianaHvacClimateEntity)


class TestSabianaHvacClimateEntityInit:
    def test_init_sets_attributes_correctly(
        self, mock_session, mock_coordinator, mock_device
    ):
        entity = SabianaHvacClimateEntity(mock_session, mock_coordinator, mock_device)
        assert entity._session == mock_session
        assert entity._coordinator == mock_coordinator
        assert entity._device == mock_device
        assert entity.unique_id == "device1"
        assert entity.name == "Test Device"
        assert entity.hvac_mode == HVACMode.OFF
        assert entity.target_temperature == 25.0
        assert entity.fan_mode == FAN_AUTO
        assert entity.swing_mode == "Swing"
        assert entity.preset_mode is None

    def test_init_sets_class_attributes(self, mock_session, mock_coordinator, mock_device):
        entity = SabianaHvacClimateEntity(mock_session, mock_coordinator, mock_device)
        assert HVACMode.OFF in entity.hvac_modes
        assert HVACMode.COOL in entity.hvac_modes
        assert HVACMode.HEAT in entity.hvac_modes
        assert HVACMode.FAN_ONLY in entity.hvac_modes
        assert FAN_LOW in entity.fan_modes
        assert FAN_MEDIUM in entity.fan_modes
        assert FAN_HIGH in entity.fan_modes
        assert FAN_AUTO in entity.fan_modes
        assert "Vertical" in entity.swing_modes
        assert "Horizontal" in entity.swing_modes
        assert "45 Degrees" in entity.swing_modes
        assert "Swing" in entity.swing_modes
        assert PRESET_SLEEP in entity.preset_modes
        assert PRESET_NONE in entity.preset_modes
        assert entity.temperature_unit == UnitOfTemperature.CELSIUS
        assert entity.min_temp == 10.0
        assert entity.max_temp == 30.0
        assert entity.target_temperature_step == 0.5


class TestSabianaHvacClimateEntityCelsiusToHex:
    def test_celsius_to_hex_converts_temperature_correctly(self, entity):
        assert entity._celsius_to_hex(25.0) == "00fa"
        assert entity._celsius_to_hex(20.0) == "00c8"
        assert entity._celsius_to_hex(30.0) == "012c"
        assert entity._celsius_to_hex(10.0) == "0064"

    def test_celsius_to_hex_handles_decimal_temperatures(self, entity):
        assert entity._celsius_to_hex(25.5) == "00ff"
        assert entity._celsius_to_hex(20.3) == "00cb"


class TestSabianaHvacClimateEntityMapFanMode:
    def test_map_fan_mode_to_sabiana_char_returns_correct_values(self, entity):
        assert entity._map_fan_mode_to_sabiana_char(FAN_LOW) == "1"
        assert entity._map_fan_mode_to_sabiana_char(FAN_MEDIUM) == "2"
        assert entity._map_fan_mode_to_sabiana_char(FAN_HIGH) == "3"
        assert entity._map_fan_mode_to_sabiana_char(FAN_AUTO) == "4"

    def test_map_fan_mode_to_sabiana_char_returns_default_for_unknown(self, entity):
        assert entity._map_fan_mode_to_sabiana_char("unknown") == "4"
        assert entity._map_fan_mode_to_sabiana_char(None) == "4"


class TestSabianaHvacClimateEntityMapHvacMode:
    def test_map_hvac_mode_to_sabiana_char_returns_correct_values(self, entity):
        assert entity._map_hvac_mode_to_sabiana_char(HVACMode.COOL) == "0"
        assert entity._map_hvac_mode_to_sabiana_char(HVACMode.HEAT) == "1"
        assert entity._map_hvac_mode_to_sabiana_char(HVACMode.FAN_ONLY) == "3"
        assert entity._map_hvac_mode_to_sabiana_char(HVACMode.OFF) == "4"

    def test_map_hvac_mode_to_sabiana_char_returns_default_for_unknown(self, entity):
        assert entity._map_hvac_mode_to_sabiana_char(None) == "4"


class TestSabianaHvacClimateEntityMapSwingMode:
    def test_map_swing_mode_to_sabiana_char_returns_correct_values(self, entity):
        assert entity._map_swing_mode_to_sabiana_char("Vertical") == "3"
        assert entity._map_swing_mode_to_sabiana_char("Horizontal") == "1"
        assert entity._map_swing_mode_to_sabiana_char("45 Degrees") == "2"
        assert entity._map_swing_mode_to_sabiana_char("Swing") == "4"

    def test_map_swing_mode_to_sabiana_char_returns_default_for_unknown(self, entity):
        assert entity._map_swing_mode_to_sabiana_char("unknown") == "4"
        assert entity._map_swing_mode_to_sabiana_char(None) == "4"


class TestSabianaHvacClimateEntityMapPresetMode:
    def test_map_preset_mode_to_sabiana_char_returns_sleep_for_sleep(self, entity):
        assert entity._map_preset_mode_to_sabiana_char(PRESET_SLEEP) == "2"

    def test_map_preset_mode_to_sabiana_char_returns_zero_for_other(self, entity):
        assert entity._map_preset_mode_to_sabiana_char(PRESET_NONE) == "0"
        assert entity._map_preset_mode_to_sabiana_char(None) == "0"
        assert entity._map_preset_mode_to_sabiana_char("other") == "0"


class TestSabianaHvacClimateEntityBuildCommandPayload:
    def test_build_command_payload_creates_correct_format(self, entity):
        entity._attr_hvac_mode = HVACMode.COOL
        entity._attr_target_temperature = 25.0
        entity._attr_fan_mode = FAN_AUTO
        entity._attr_swing_mode = "Swing"
        entity._attr_preset_mode = None
        result = entity._build_command_payload()
        assert result.startswith("0")
        assert "00fa" in result
        assert len(result) > 10

    def test_build_command_payload_includes_all_components(self, entity):
        entity._attr_hvac_mode = HVACMode.HEAT
        entity._attr_target_temperature = 20.0
        entity._attr_fan_mode = FAN_HIGH
        entity._attr_swing_mode = "Vertical"
        entity._attr_preset_mode = PRESET_SLEEP
        result = entity._build_command_payload()
        assert "03" in result
        assert "01" in result
        assert "00c8" in result
        assert "2" in result


class TestSabianaHvacClimateEntityAsyncExecuteCommand:
    @pytest.mark.asyncio
    async def test_async_execute_command_sends_command_successfully(
        self, entity, mock_session, mock_coordinator
    ):
        with patch(
            "custom_components.sabiana_hvac.climate.api.async_send_command",
            return_value=True,
        ) as mock_send:
            entity.async_write_ha_state = Mock()
            await entity._async_execute_command()
            mock_send.assert_called_once()
            entity.async_write_ha_state.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_execute_command_handles_auth_error(
        self, entity, mock_session, mock_coordinator
    ):
        with patch(
            "custom_components.sabiana_hvac.climate.api.async_send_command",
            side_effect=SabianaApiAuthError("Auth failed"),
        ):
            entity.async_write_ha_state = Mock()
            await entity._async_execute_command()
            entity.async_write_ha_state.assert_not_called()

    @pytest.mark.asyncio
    async def test_async_execute_command_handles_client_error(
        self, entity, mock_session, mock_coordinator
    ):
        with patch(
            "custom_components.sabiana_hvac.climate.api.async_send_command",
            side_effect=SabianaApiClientError("API error"),
        ):
            entity.async_write_ha_state = Mock()
            await entity._async_execute_command()
            entity.async_write_ha_state.assert_not_called()

    @pytest.mark.asyncio
    async def test_async_execute_command_handles_request_error(
        self, entity, mock_session, mock_coordinator
    ):
        with patch(
            "custom_components.sabiana_hvac.climate.api.async_send_command",
            side_effect=httpx.RequestError("Connection error"),
        ):
            entity.async_write_ha_state = Mock()
            await entity._async_execute_command()
            entity.async_write_ha_state.assert_not_called()

    @pytest.mark.asyncio
    async def test_async_execute_command_handles_unexpected_error(
        self, entity, mock_session, mock_coordinator
    ):
        with patch(
            "custom_components.sabiana_hvac.climate.api.async_send_command",
            side_effect=Exception("Unexpected error"),
        ):
            entity.async_write_ha_state = Mock()
            await entity._async_execute_command()
            entity.async_write_ha_state.assert_not_called()


class TestSabianaHvacClimateEntityAsyncAddedToHass:
    @pytest.mark.asyncio
    async def test_async_added_to_hass_registers_listener(self, entity, mock_coordinator):
        entity.async_get_last_state = AsyncMock(return_value=None)
        with patch.object(entity, "async_get_last_state", return_value=None):
            await entity.async_added_to_hass()
            mock_coordinator.async_add_listener.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_added_to_hass_restores_state_when_available(self, entity):
        last_state = Mock()
        last_state.state = HVACMode.COOL
        last_state.attributes = {
            ATTR_TEMPERATURE: 22.0,
            "fan_mode": FAN_HIGH,
            "swing_mode": "Vertical",
            "preset_mode": PRESET_SLEEP,
        }
        entity.async_get_last_state = AsyncMock(return_value=last_state)
        await entity.async_added_to_hass()
        assert entity.hvac_mode == HVACMode.COOL
        assert entity.target_temperature == 22.0
        assert entity.fan_mode == FAN_HIGH
        assert entity.swing_mode == "Vertical"
        assert entity.preset_mode == PRESET_SLEEP

    @pytest.mark.asyncio
    async def test_async_added_to_hass_handles_missing_state(self, entity):
        entity.async_get_last_state = AsyncMock(return_value=None)
        await entity.async_added_to_hass()
        assert entity.hvac_mode == HVACMode.OFF


class TestSabianaHvacClimateEntityAsyncWillRemoveFromHass:
    @pytest.mark.asyncio
    async def test_async_will_remove_from_hass_unsubscribes_listener(self, entity):
        mock_unsub = Mock()
        entity._coordinator_listener_unsub = mock_unsub
        await entity.async_will_remove_from_hass()
        mock_unsub.assert_called_once()
        assert entity._coordinator_listener_unsub is None

    @pytest.mark.asyncio
    async def test_async_will_remove_from_hass_handles_no_listener(self, entity):
        entity._coordinator_listener_unsub = None
        await entity.async_will_remove_from_hass()
        assert entity._coordinator_listener_unsub is None


class TestSabianaHvacClimateEntityAsyncSetHvacMode:
    @pytest.mark.asyncio
    async def test_async_set_hvac_mode_updates_mode_and_executes_command(
        self, entity
    ):
        entity._async_execute_command = AsyncMock()
        await entity.async_set_hvac_mode(HVACMode.COOL)
        assert entity.hvac_mode == HVACMode.COOL
        entity._async_execute_command.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_set_hvac_mode_handles_all_modes(self, entity):
        entity._async_execute_command = AsyncMock()
        for mode in [HVACMode.OFF, HVACMode.COOL, HVACMode.HEAT, HVACMode.FAN_ONLY]:
            await entity.async_set_hvac_mode(mode)
            assert entity.hvac_mode == mode


class TestSabianaHvacClimateEntityAsyncSetTemperature:
    @pytest.mark.asyncio
    async def test_async_set_temperature_updates_temperature(self, entity):
        entity.async_write_ha_state = Mock()
        entity._async_execute_command = AsyncMock()
        entity._attr_hvac_mode = HVACMode.COOL
        await entity.async_set_temperature(**{ATTR_TEMPERATURE: 22.0})
        assert entity.target_temperature == 22.0
        entity.async_write_ha_state.assert_called_once()
        entity._async_execute_command.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_set_temperature_does_not_execute_when_off(self, entity):
        entity.async_write_ha_state = Mock()
        entity._async_execute_command = AsyncMock()
        entity._attr_hvac_mode = HVACMode.OFF
        await entity.async_set_temperature(**{ATTR_TEMPERATURE: 22.0})
        assert entity.target_temperature == 22.0
        entity.async_write_ha_state.assert_called_once()
        entity._async_execute_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_async_set_temperature_does_not_execute_when_temperature_none(
        self, entity
    ):
        entity.async_write_ha_state = Mock()
        entity._async_execute_command = AsyncMock()
        entity._attr_hvac_mode = HVACMode.COOL
        await entity.async_set_temperature(**{ATTR_TEMPERATURE: None})
        entity.async_write_ha_state.assert_called_once()
        entity._async_execute_command.assert_not_called()


class TestSabianaHvacClimateEntityAsyncSetFanMode:
    @pytest.mark.asyncio
    async def test_async_set_fan_mode_updates_mode_and_executes_when_on(self, entity):
        entity.async_write_ha_state = Mock()
        entity._async_execute_command = AsyncMock()
        entity._attr_hvac_mode = HVACMode.COOL
        await entity.async_set_fan_mode(FAN_HIGH)
        assert entity.fan_mode == FAN_HIGH
        entity.async_write_ha_state.assert_called_once()
        entity._async_execute_command.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_set_fan_mode_does_not_execute_when_off(self, entity):
        entity.async_write_ha_state = Mock()
        entity._async_execute_command = AsyncMock()
        entity._attr_hvac_mode = HVACMode.OFF
        await entity.async_set_fan_mode(FAN_HIGH)
        assert entity.fan_mode == FAN_HIGH
        entity.async_write_ha_state.assert_called_once()
        entity._async_execute_command.assert_not_called()


class TestSabianaHvacClimateEntityAsyncSetSwingMode:
    @pytest.mark.asyncio
    async def test_async_set_swing_mode_updates_mode_and_executes_when_on(self, entity):
        entity.async_write_ha_state = Mock()
        entity._async_execute_command = AsyncMock()
        entity._attr_hvac_mode = HVACMode.COOL
        await entity.async_set_swing_mode("Vertical")
        assert entity.swing_mode == "Vertical"
        entity.async_write_ha_state.assert_called_once()
        entity._async_execute_command.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_set_swing_mode_does_not_execute_when_off(self, entity):
        entity.async_write_ha_state = Mock()
        entity._async_execute_command = AsyncMock()
        entity._attr_hvac_mode = HVACMode.OFF
        await entity.async_set_swing_mode("Vertical")
        assert entity.swing_mode == "Vertical"
        entity.async_write_ha_state.assert_called_once()
        entity._async_execute_command.assert_not_called()


class TestSabianaHvacClimateEntityAsyncSetPresetMode:
    @pytest.mark.asyncio
    async def test_async_set_preset_mode_updates_mode_and_executes_when_on(self, entity):
        entity.async_write_ha_state = Mock()
        entity._async_execute_command = AsyncMock()
        entity._attr_hvac_mode = HVACMode.COOL
        await entity.async_set_preset_mode(PRESET_SLEEP)
        assert entity.preset_mode == PRESET_SLEEP
        entity.async_write_ha_state.assert_called_once()
        entity._async_execute_command.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_set_preset_mode_does_not_execute_when_off(self, entity):
        entity.async_write_ha_state = Mock()
        entity._async_execute_command = AsyncMock()
        entity._attr_hvac_mode = HVACMode.OFF
        await entity.async_set_preset_mode(PRESET_SLEEP)
        assert entity.preset_mode == PRESET_SLEEP
        entity.async_write_ha_state.assert_called_once()
        entity._async_execute_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_async_set_preset_mode_handles_none(self, entity):
        entity.async_write_ha_state = Mock()
        entity._async_execute_command = AsyncMock()
        entity._attr_hvac_mode = HVACMode.COOL
        await entity.async_set_preset_mode(None)
        assert entity.preset_mode is None
        entity.async_write_ha_state.assert_called_once()
        entity._async_execute_command.assert_called_once()


class TestSabianaHvacClimateEntityAsyncTurnOn:
    @pytest.mark.asyncio
    async def test_async_turn_on_sets_fan_only_mode(self, entity):
        entity.async_set_hvac_mode = AsyncMock()
        await entity.async_turn_on()
        entity.async_set_hvac_mode.assert_called_once_with(HVACMode.FAN_ONLY)


class TestSabianaHvacClimateEntityAsyncTurnOff:
    @pytest.mark.asyncio
    async def test_async_turn_off_sets_off_mode(self, entity):
        entity.async_set_hvac_mode = AsyncMock()
        await entity.async_turn_off()
        entity.async_set_hvac_mode.assert_called_once_with(HVACMode.OFF)

