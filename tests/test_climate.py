"""Tests for the Sabiana HVAC Climate entity."""

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
from custom_components.sabiana_hvac.api import (
    SabianaApiAuthError,
    SabianaApiClientError,
)
from custom_components.sabiana_hvac.climate import (
    SabianaHvacClimateEntity,
    async_setup_entry,
)

DEFAULT_TARGET_TEMP = 25.0
MIN_TEMP = 10.0
MAX_TEMP = 30.0
TEMP_STEP = 0.5
TEST_TARGET_TEMP = 22.0
MIN_RESULT_LENGTH = 10


@pytest.fixture
def mock_hass() -> Mock:
    """Create a mock Home Assistant instance."""
    hass = Mock()
    hass.data = {}
    return hass


@pytest.fixture
def mock_session() -> Mock:
    """Create a mock HTTP session."""
    return Mock(spec=httpx.AsyncClient)


@pytest.fixture
def mock_coordinator() -> Mock:
    """Create a mock token coordinator."""
    coordinator = Mock()
    coordinator.short_jwt = Mock()
    jwt_value = "test_jwt_token"
    coordinator.short_jwt.token = jwt_value
    coordinator.async_add_listener = Mock(return_value=Mock())
    return coordinator


@pytest.fixture
def mock_device_coordinator() -> Mock:
    """Create a mock device coordinator."""
    coordinator = Mock()
    coordinator.data = {}
    coordinator.async_add_listener = Mock(return_value=Mock())
    coordinator.async_request_refresh = AsyncMock()
    return coordinator


@pytest.fixture
def mock_device() -> api.SabianaDevice:
    """Create a mock Sabiana device."""
    return api.SabianaDevice(id="device1", name="Test Device")


@pytest.fixture
def entity(
    mock_session: Mock,
    mock_coordinator: Mock,
    mock_device_coordinator: Mock,
    mock_device: api.SabianaDevice,
) -> SabianaHvacClimateEntity:
    """Create a Sabiana HVAC Climate entity for testing."""
    return SabianaHvacClimateEntity(
        mock_session, mock_coordinator, mock_device_coordinator, mock_device
    )


class TestAsyncSetupEntry:
    """Tests for async_setup_entry function."""

    @pytest.mark.asyncio
    async def test_async_setup_entry_creates_entities_for_all_devices(
        self,
        mock_hass: Mock,
        mock_session: Mock,
        mock_coordinator: Mock,
        mock_device_coordinator: Mock,
        mock_device: api.SabianaDevice,
    ) -> None:
        """Test that async_setup_entry creates entities for all devices."""
        entry = Mock()
        entry.entry_id = "test_entry"
        mock_hass.data["sabiana_hvac"] = {
            "test_entry": {
                "session": mock_session,
                "token_coordinator": mock_coordinator,
                "device_coordinator": mock_device_coordinator,
                "devices": [mock_device],
            },
        }
        async_add_entities = AsyncMock()
        await async_setup_entry(mock_hass, entry, async_add_entities)
        async_add_entities.assert_called_once()
        assert len(async_add_entities.call_args[0][0]) == 1
        assert isinstance(
            async_add_entities.call_args[0][0][0],
            SabianaHvacClimateEntity,
        )


class TestSabianaHvacClimateEntityInit:
    """Tests for SabianaHvacClimateEntity initialization."""

    def test_init_sets_attributes_correctly(
        self,
        mock_session: Mock,
        mock_coordinator: Mock,
        mock_device_coordinator: Mock,
        mock_device: api.SabianaDevice,
    ) -> None:
        """Test that init sets attributes correctly."""
        entity = SabianaHvacClimateEntity(
            mock_session, mock_coordinator, mock_device_coordinator, mock_device
        )
        assert entity._session == mock_session
        assert entity._coordinator == mock_coordinator
        assert entity._device_coordinator == mock_device_coordinator
        assert entity._device == mock_device
        assert entity.unique_id == "device1"
        assert entity.name == "Test Device"
        assert entity.hvac_mode == HVACMode.OFF
        assert entity.target_temperature == DEFAULT_TARGET_TEMP
        assert entity.fan_mode == FAN_AUTO
        assert entity.swing_mode == "off"
        assert entity.preset_mode == PRESET_NONE

    def test_init_sets_class_attributes(
        self,
        mock_session: Mock,
        mock_coordinator: Mock,
        mock_device_coordinator: Mock,
        mock_device: api.SabianaDevice,
    ) -> None:
        """Test that init sets class attributes correctly."""
        entity = SabianaHvacClimateEntity(
            mock_session, mock_coordinator, mock_device_coordinator, mock_device
        )
        assert HVACMode.OFF in entity.hvac_modes
        assert HVACMode.COOL in entity.hvac_modes
        assert HVACMode.HEAT in entity.hvac_modes
        assert HVACMode.FAN_ONLY in entity.hvac_modes
        assert FAN_LOW in entity.fan_modes
        assert FAN_MEDIUM in entity.fan_modes
        assert FAN_HIGH in entity.fan_modes
        assert FAN_AUTO in entity.fan_modes
        # Swing modes are now empty (not supported)
        assert entity.swing_modes == []
        assert PRESET_SLEEP in entity.preset_modes
        assert PRESET_NONE in entity.preset_modes
        assert entity.temperature_unit == UnitOfTemperature.CELSIUS
        assert entity.min_temp == MIN_TEMP
        assert entity.max_temp == MAX_TEMP
        assert entity.target_temperature_step == TEMP_STEP


class TestSabianaHvacClimateEntityCelsiusToHex:
    """Tests for _celsius_to_hex method."""

    def test_celsius_to_hex_converts_temperature_correctly(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that _celsius_to_hex converts temperature correctly."""
        assert entity._celsius_to_hex(25.0) == "00fa"
        assert entity._celsius_to_hex(20.0) == "00c8"
        assert entity._celsius_to_hex(30.0) == "012c"
        assert entity._celsius_to_hex(10.0) == "0064"

    def test_celsius_to_hex_handles_decimal_temperatures(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that _celsius_to_hex handles decimal temperatures."""
        assert entity._celsius_to_hex(25.5) == "00ff"
        assert entity._celsius_to_hex(20.3) == "00cb"


class TestSabianaHvacClimateEntityMapFanMode:
    """Tests for _map_fan_mode_to_sabiana_char method."""

    def test_map_fan_mode_to_sabiana_char_returns_correct_values(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that _map_fan_mode_to_sabiana_char returns correct values."""
        assert entity._map_fan_mode_to_sabiana_char(FAN_LOW) == "1"
        assert entity._map_fan_mode_to_sabiana_char(FAN_MEDIUM) == "2"
        assert entity._map_fan_mode_to_sabiana_char(FAN_HIGH) == "3"
        assert entity._map_fan_mode_to_sabiana_char(FAN_AUTO) == "4"

    def test_map_fan_mode_to_sabiana_char_returns_default_for_unknown(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that _map_fan_mode_to_sabiana_char returns default for unknown."""
        assert entity._map_fan_mode_to_sabiana_char("unknown") == "4"
        assert entity._map_fan_mode_to_sabiana_char(None) == "4"


class TestSabianaHvacClimateEntityMapHvacMode:
    """Tests for _map_hvac_mode_to_sabiana_char method."""

    def test_map_hvac_mode_to_sabiana_char_returns_correct_values(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that _map_hvac_mode_to_sabiana_char returns correct values."""
        assert entity._map_hvac_mode_to_sabiana_char(HVACMode.COOL) == "0"
        assert entity._map_hvac_mode_to_sabiana_char(HVACMode.HEAT) == "1"
        assert entity._map_hvac_mode_to_sabiana_char(HVACMode.FAN_ONLY) == "3"
        assert entity._map_hvac_mode_to_sabiana_char(HVACMode.OFF) == "4"

    def test_map_hvac_mode_to_sabiana_char_returns_default_for_unknown(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that _map_hvac_mode_to_sabiana_char returns default for unknown."""
        assert entity._map_hvac_mode_to_sabiana_char(None) == "4"


class TestSabianaHvacClimateEntityMapSwingMode:
    """Tests for _map_swing_mode_to_sabiana_char method."""

    def test_map_swing_mode_to_sabiana_char_returns_correct_values(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that _map_swing_mode_to_sabiana_char returns correct values."""
        assert entity._map_swing_mode_to_sabiana_char("Vertical") == "3"
        assert entity._map_swing_mode_to_sabiana_char("Horizontal") == "1"
        assert entity._map_swing_mode_to_sabiana_char("45 Degrees") == "2"
        assert entity._map_swing_mode_to_sabiana_char("Swing") == "4"

    def test_map_swing_mode_to_sabiana_char_returns_default_for_unknown(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that _map_swing_mode_to_sabiana_char returns default for unknown."""
        assert entity._map_swing_mode_to_sabiana_char("unknown") == "4"
        assert entity._map_swing_mode_to_sabiana_char(None) == "4"


class TestSabianaHvacClimateEntityMapPresetMode:
    """Tests for _map_preset_mode_to_sabiana_char method."""

    def test_map_preset_mode_to_sabiana_char_returns_sleep_for_sleep(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that _map_preset_mode_to_sabiana_char returns sleep for sleep."""
        assert entity._map_preset_mode_to_sabiana_char(PRESET_SLEEP) == "2"

    def test_map_preset_mode_to_sabiana_char_returns_zero_for_other(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that _map_preset_mode_to_sabiana_char returns zero for other."""
        assert entity._map_preset_mode_to_sabiana_char(PRESET_NONE) == "0"
        assert entity._map_preset_mode_to_sabiana_char(None) == "0"
        assert entity._map_preset_mode_to_sabiana_char("other") == "0"


class TestSabianaHvacClimateEntityBuildCommandPayload:
    """Tests for _build_command_payload method."""

    def test_build_command_payload_creates_correct_format(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that _build_command_payload creates correct format."""
        entity._attr_hvac_mode = HVACMode.COOL
        entity._attr_target_temperature = 25.0
        entity._attr_fan_mode = FAN_AUTO
        entity._attr_swing_mode = "Swing"
        entity._attr_preset_mode = None
        result = entity._build_command_payload()
        assert result.startswith("0")
        assert "00fa" in result
        assert len(result) > MIN_RESULT_LENGTH

    def test_build_command_payload_includes_all_components(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that _build_command_payload includes all components."""
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
    """Tests for _async_execute_command method."""

    @pytest.mark.asyncio
    async def test_async_execute_command_sends_command_successfully(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that _async_execute_command sends command successfully."""
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
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that _async_execute_command handles auth error."""
        error_message = "Auth failed"
        with patch(
            "custom_components.sabiana_hvac.climate.api.async_send_command",
            side_effect=SabianaApiAuthError(error_message),
        ):
            entity.async_write_ha_state = Mock()
            await entity._async_execute_command()
            entity.async_write_ha_state.assert_not_called()

    @pytest.mark.asyncio
    async def test_async_execute_command_handles_client_error(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that _async_execute_command handles client error."""
        error_message = "API error"
        with patch(
            "custom_components.sabiana_hvac.climate.api.async_send_command",
            side_effect=SabianaApiClientError(error_message),
        ):
            entity.async_write_ha_state = Mock()
            await entity._async_execute_command()
            entity.async_write_ha_state.assert_not_called()

    @pytest.mark.asyncio
    async def test_async_execute_command_handles_request_error(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that _async_execute_command handles request error."""
        error_message = "Connection error"
        with patch(
            "custom_components.sabiana_hvac.climate.api.async_send_command",
            side_effect=httpx.RequestError(error_message),
        ):
            entity.async_write_ha_state = Mock()
            await entity._async_execute_command()
            entity.async_write_ha_state.assert_not_called()

    @pytest.mark.asyncio
    async def test_async_execute_command_handles_unexpected_error(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that _async_execute_command handles unexpected error."""
        error_message = "Unexpected error"
        with patch(
            "custom_components.sabiana_hvac.climate.api.async_send_command",
            side_effect=Exception(error_message),
        ):
            entity.async_write_ha_state = Mock()
            await entity._async_execute_command()
            entity.async_write_ha_state.assert_not_called()


class TestSabianaHvacClimateEntityAsyncAddedToHass:
    """Tests for async_added_to_hass method."""

    @pytest.mark.asyncio
    async def test_async_added_to_hass_registers_listener(
        self,
        entity: SabianaHvacClimateEntity,
        mock_device_coordinator: Mock,
    ) -> None:
        """Test that async_added_to_hass registers listener."""
        entity.async_get_last_state = AsyncMock(return_value=None)
        with patch.object(entity, "async_get_last_state", return_value=None):
            await entity.async_added_to_hass()
            mock_device_coordinator.async_add_listener.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_added_to_hass_restores_state_when_available(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that async_added_to_hass restores state when available."""
        last_state = Mock()
        last_state.state = HVACMode.COOL
        last_state.attributes = {
            ATTR_TEMPERATURE: TEST_TARGET_TEMP,
            "fan_mode": FAN_HIGH,
            "swing_mode": "Vertical",
            "preset_mode": PRESET_SLEEP,
        }
        entity.async_get_last_state = AsyncMock(return_value=last_state)
        await entity.async_added_to_hass()
        assert entity.hvac_mode == HVACMode.COOL
        assert entity.target_temperature == TEST_TARGET_TEMP
        assert entity.fan_mode == FAN_HIGH
        assert entity.swing_mode == "Vertical"
        assert entity.preset_mode == PRESET_SLEEP

    @pytest.mark.asyncio
    async def test_async_added_to_hass_handles_missing_state(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that async_added_to_hass handles missing state."""
        entity.async_get_last_state = AsyncMock(return_value=None)
        await entity.async_added_to_hass()
        assert entity.hvac_mode == HVACMode.OFF


class TestSabianaHvacClimateEntityAsyncWillRemoveFromHass:
    """Tests for async_will_remove_from_hass method."""

    @pytest.mark.asyncio
    async def test_async_will_remove_from_hass_unsubscribes_listener(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that async_will_remove_from_hass unsubscribes listener."""
        mock_unsub = Mock()
        entity._coordinator_listener_unsub = mock_unsub
        await entity.async_will_remove_from_hass()
        mock_unsub.assert_called_once()
        assert entity._coordinator_listener_unsub is None

    @pytest.mark.asyncio
    async def test_async_will_remove_from_hass_handles_no_listener(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that async_will_remove_from_hass handles no listener."""
        entity._coordinator_listener_unsub = None
        await entity.async_will_remove_from_hass()
        assert entity._coordinator_listener_unsub is None


class TestSabianaHvacClimateEntityAsyncSetHvacMode:
    """Tests for async_set_hvac_mode method."""

    @pytest.mark.asyncio
    async def test_async_set_hvac_mode_updates_mode_and_executes_command(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that async_set_hvac_mode updates mode and executes command."""
        entity._async_execute_command = AsyncMock()
        await entity.async_set_hvac_mode(HVACMode.COOL)
        assert entity.hvac_mode == HVACMode.COOL
        entity._async_execute_command.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_set_hvac_mode_handles_all_modes(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that async_set_hvac_mode handles all modes."""
        entity._async_execute_command = AsyncMock()
        for mode in [HVACMode.OFF, HVACMode.COOL, HVACMode.HEAT, HVACMode.FAN_ONLY]:
            await entity.async_set_hvac_mode(mode)
            assert entity.hvac_mode == mode


class TestSabianaHvacClimateEntityAsyncSetTemperature:
    """Tests for async_set_temperature method."""

    @pytest.mark.asyncio
    async def test_async_set_temperature_updates_temperature(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that async_set_temperature updates temperature."""
        entity.async_write_ha_state = Mock()
        entity._async_execute_command = AsyncMock()
        entity._attr_hvac_mode = HVACMode.COOL
        await entity.async_set_temperature(**{ATTR_TEMPERATURE: TEST_TARGET_TEMP})
        assert entity.target_temperature == TEST_TARGET_TEMP
        entity.async_write_ha_state.assert_called_once()
        entity._async_execute_command.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_set_temperature_does_not_execute_when_off(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that async_set_temperature does not execute when off."""
        entity.async_write_ha_state = Mock()
        entity._async_execute_command = AsyncMock()
        entity._attr_hvac_mode = HVACMode.OFF
        await entity.async_set_temperature(**{ATTR_TEMPERATURE: TEST_TARGET_TEMP})
        assert entity.target_temperature == TEST_TARGET_TEMP
        entity.async_write_ha_state.assert_called_once()
        entity._async_execute_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_async_set_temperature_does_not_execute_when_temperature_none(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that async_set_temperature does not execute when temperature is None."""
        entity.async_write_ha_state = Mock()
        entity._async_execute_command = AsyncMock()
        entity._attr_hvac_mode = HVACMode.COOL
        await entity.async_set_temperature(**{ATTR_TEMPERATURE: None})
        entity.async_write_ha_state.assert_called_once()
        entity._async_execute_command.assert_not_called()


class TestSabianaHvacClimateEntityAsyncSetFanMode:
    """Tests for async_set_fan_mode method."""

    @pytest.mark.asyncio
    async def test_async_set_fan_mode_updates_mode_and_executes_when_on(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that async_set_fan_mode updates mode and executes when on."""
        entity.async_write_ha_state = Mock()
        entity._async_execute_command = AsyncMock()
        entity._attr_hvac_mode = HVACMode.COOL
        await entity.async_set_fan_mode(FAN_HIGH)
        assert entity.fan_mode == FAN_HIGH
        entity.async_write_ha_state.assert_called_once()
        entity._async_execute_command.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_set_fan_mode_does_not_execute_when_off(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that async_set_fan_mode does not execute when off."""
        entity.async_write_ha_state = Mock()
        entity._async_execute_command = AsyncMock()
        entity._attr_hvac_mode = HVACMode.OFF
        await entity.async_set_fan_mode(FAN_HIGH)
        assert entity.fan_mode == FAN_HIGH
        entity.async_write_ha_state.assert_called_once()
        entity._async_execute_command.assert_not_called()


class TestSabianaHvacClimateEntityAsyncSetSwingMode:
    """Tests for async_set_swing_mode method."""

    @pytest.mark.asyncio
    async def test_async_set_swing_mode_updates_mode_and_executes_when_on(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that async_set_swing_mode updates mode and executes when on."""
        entity.async_write_ha_state = Mock()
        entity._async_execute_command = AsyncMock()
        entity._attr_hvac_mode = HVACMode.COOL
        await entity.async_set_swing_mode("Vertical")
        assert entity.swing_mode == "Vertical"
        entity.async_write_ha_state.assert_called_once()
        entity._async_execute_command.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_set_swing_mode_does_not_execute_when_off(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that async_set_swing_mode does not execute when off."""
        entity.async_write_ha_state = Mock()
        entity._async_execute_command = AsyncMock()
        entity._attr_hvac_mode = HVACMode.OFF
        await entity.async_set_swing_mode("Vertical")
        assert entity.swing_mode == "Vertical"
        entity.async_write_ha_state.assert_called_once()
        entity._async_execute_command.assert_not_called()


class TestSabianaHvacClimateEntityAsyncSetPresetMode:
    """Tests for async_set_preset_mode method."""

    @pytest.mark.asyncio
    async def test_async_set_preset_mode_updates_mode_and_executes_when_on(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that async_set_preset_mode updates mode and executes when on."""
        entity.async_write_ha_state = Mock()
        entity._async_execute_command = AsyncMock()
        entity._attr_hvac_mode = HVACMode.COOL
        await entity.async_set_preset_mode(PRESET_SLEEP)
        assert entity.preset_mode == PRESET_SLEEP
        entity.async_write_ha_state.assert_called_once()
        entity._async_execute_command.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_set_preset_mode_does_not_execute_when_off(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that async_set_preset_mode does not execute when off."""
        entity.async_write_ha_state = Mock()
        entity._async_execute_command = AsyncMock()
        entity._attr_hvac_mode = HVACMode.OFF
        await entity.async_set_preset_mode(PRESET_SLEEP)
        assert entity.preset_mode == PRESET_SLEEP
        entity.async_write_ha_state.assert_called_once()
        entity._async_execute_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_async_set_preset_mode_handles_none(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that async_set_preset_mode handles None."""
        entity.async_write_ha_state = Mock()
        entity._async_execute_command = AsyncMock()
        entity._attr_hvac_mode = HVACMode.COOL
        await entity.async_set_preset_mode(None)
        assert entity.preset_mode is None
        entity.async_write_ha_state.assert_called_once()
        entity._async_execute_command.assert_called_once()


class TestSabianaHvacClimateEntityAsyncTurnOn:
    """Tests for async_turn_on method."""

    @pytest.mark.asyncio
    async def test_async_turn_on_sets_fan_only_mode(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that async_turn_on sets fan only mode."""
        entity.async_set_hvac_mode = AsyncMock()
        await entity.async_turn_on()
        entity.async_set_hvac_mode.assert_called_once_with(HVACMode.FAN_ONLY)


class TestSabianaHvacClimateEntityAsyncTurnOff:
    """Tests for async_turn_off method."""

    @pytest.mark.asyncio
    async def test_async_turn_off_sets_off_mode(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that async_turn_off sets off mode."""
        entity.async_set_hvac_mode = AsyncMock()
        await entity.async_turn_off()
        entity.async_set_hvac_mode.assert_called_once_with(HVACMode.OFF)
