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
    DeviceState,
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


def _make_state(
    *,
    is_on: bool = True,
    mode: str = "cooling",
    heating_temp: float = 21.0,
    cooling_temp: float = 24.0,
    current_temp: float = 22.5,
    fan_speed: int = 1,
    fan_auto: bool = False,
    night_mode: bool = False,
) -> DeviceState:
    """Build a DeviceState with sensible defaults for entity tests."""
    return DeviceState(
        is_on=is_on,
        mode=mode,
        heating_temp=heating_temp,
        cooling_temp=cooling_temp,
        current_temp=current_temp,
        fan_speed=fan_speed,
        fan_auto=fan_auto,
        night_mode=night_mode,
    )


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
def mock_token_coordinator() -> Mock:
    """Create a mock token coordinator exposing short_jwt.token."""
    coordinator = Mock()
    coordinator.short_jwt = Mock()
    coordinator.short_jwt.token = "test_jwt_token"
    return coordinator


@pytest.fixture
def mock_device_coordinator() -> Mock:
    """Create a mock device-state coordinator.

    ``data`` starts as an empty dict so ``_current_state`` returns None, and
    ``async_request_refresh`` is awaitable so commands can trigger a refresh.
    """
    coordinator = Mock()
    coordinator.data = {}
    coordinator.last_update_success = True
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
    mock_token_coordinator: Mock,
    mock_device_coordinator: Mock,
    mock_device: api.SabianaDevice,
) -> SabianaHvacClimateEntity:
    """Create a Sabiana HVAC Climate entity with empty coordinator data."""
    return SabianaHvacClimateEntity(
        mock_session,
        mock_token_coordinator,
        mock_device_coordinator,
        mock_device,
    )


class TestAsyncSetupEntry:
    """Tests for async_setup_entry function."""

    @pytest.mark.asyncio
    async def test_async_setup_entry_creates_entities_for_all_devices(
        self,
        mock_hass: Mock,
        mock_session: Mock,
        mock_token_coordinator: Mock,
        mock_device_coordinator: Mock,
        mock_device: api.SabianaDevice,
    ) -> None:
        """Test that async_setup_entry creates entities for all devices."""
        entry = Mock()
        entry.entry_id = "test_entry"
        mock_hass.data["sabiana_hvac"] = {
            "test_entry": {
                "session": mock_session,
                "coordinator": mock_token_coordinator,
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

    def test_init_falls_back_to_defaults_when_no_coordinator_data(
        self,
        entity: SabianaHvacClimateEntity,
        mock_device: api.SabianaDevice,
    ) -> None:
        """Without coordinator data the entity exposes its safe defaults."""
        assert entity.unique_id == mock_device.id
        assert entity.name == mock_device.name
        assert entity.hvac_mode == HVACMode.OFF
        assert entity.target_temperature == DEFAULT_TARGET_TEMP
        assert entity.current_temperature is None
        assert entity.fan_mode == FAN_AUTO
        assert entity.preset_mode is None

    def test_init_hydrates_from_coordinator_data_when_available(
        self,
        mock_session: Mock,
        mock_token_coordinator: Mock,
        mock_device_coordinator: Mock,
        mock_device: api.SabianaDevice,
    ) -> None:
        """When the coordinator already has fresh data, the entity reflects it."""
        mock_device_coordinator.data = {
            mock_device.id: _make_state(
                is_on=True,
                mode="heating",
                heating_temp=19.5,
                current_temp=20.3,
                night_mode=True,
            ),
        }
        entity = SabianaHvacClimateEntity(
            mock_session,
            mock_token_coordinator,
            mock_device_coordinator,
            mock_device,
        )
        assert entity.hvac_mode == HVACMode.HEAT
        assert entity.target_temperature == 19.5
        assert entity.current_temperature == 20.3
        assert entity.preset_mode == PRESET_SLEEP

    def test_init_sets_class_attributes(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Test that init sets class attributes correctly."""
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
        assert entity.min_temp == MIN_TEMP
        assert entity.max_temp == MAX_TEMP
        assert entity.target_temperature_step == TEMP_STEP


class TestApplyState:
    """Tests for _apply_state and _handle_coordinator_update."""

    def test_apply_state_marks_off_when_device_powered_down(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """is_on=False pins hvac_mode to OFF regardless of the reported mode."""
        entity._apply_state(_make_state(is_on=False, mode="heating"))
        assert entity.hvac_mode == HVACMode.OFF

    def test_apply_state_picks_heating_setpoint_in_heat_mode(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Heating mode surfaces heating_temp as target; cooling_temp is ignored."""
        entity._apply_state(
            _make_state(mode="heating", heating_temp=19.0, cooling_temp=27.0),
        )
        assert entity.target_temperature == 19.0

    def test_apply_state_picks_cooling_setpoint_in_cool_mode(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Cooling mode surfaces cooling_temp as target."""
        entity._apply_state(
            _make_state(mode="cooling", heating_temp=19.0, cooling_temp=27.0),
        )
        assert entity.target_temperature == 27.0

    def test_apply_state_maps_fan_speeds(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Fan speed buckets 1/5/10 map to LOW/MEDIUM/HIGH; fan_auto → AUTO."""
        entity._apply_state(_make_state(fan_speed=1))
        assert entity.fan_mode == FAN_LOW
        entity._apply_state(_make_state(fan_speed=5))
        assert entity.fan_mode == FAN_MEDIUM
        entity._apply_state(_make_state(fan_speed=10))
        assert entity.fan_mode == FAN_HIGH
        entity._apply_state(_make_state(fan_auto=True, fan_speed=0))
        assert entity.fan_mode == FAN_AUTO

    def test_handle_coordinator_update_writes_state(
        self,
        entity: SabianaHvacClimateEntity,
        mock_device_coordinator: Mock,
        mock_device: api.SabianaDevice,
    ) -> None:
        """The CoordinatorEntity callback copies state and writes it to HA."""
        mock_device_coordinator.data = {
            mock_device.id: _make_state(
                is_on=True,
                mode="cooling",
                cooling_temp=26.0,
                current_temp=28.1,
            ),
        }
        entity.async_write_ha_state = Mock()
        entity._handle_coordinator_update()
        assert entity.hvac_mode == HVACMode.COOL
        assert entity.target_temperature == 26.0
        assert entity.current_temperature == 28.1
        entity.async_write_ha_state.assert_called_once()


class TestAvailability:
    """Tests for available property."""

    def test_available_false_when_no_state_for_device(
        self,
        entity: SabianaHvacClimateEntity,
    ) -> None:
        """Without a decoded state for this device the entity reports unavailable."""
        assert entity.available is False

    def test_available_true_when_coordinator_has_state(
        self,
        entity: SabianaHvacClimateEntity,
        mock_device_coordinator: Mock,
        mock_device: api.SabianaDevice,
    ) -> None:
        """A present decoded state flips the entity to available."""
        mock_device_coordinator.data = {mock_device.id: _make_state()}
        assert entity.available is True


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
    async def test_async_execute_command_triggers_coordinator_refresh_on_success(
        self,
        entity: SabianaHvacClimateEntity,
        mock_device_coordinator: Mock,
    ) -> None:
        """Successful command flushes state and requests a coordinator refresh."""
        with patch(
            "custom_components.sabiana_hvac.climate.api.async_send_command",
            return_value=True,
        ) as mock_send:
            entity.async_write_ha_state = Mock()
            await entity._async_execute_command()
            mock_send.assert_called_once()
            entity.async_write_ha_state.assert_called_once()
            mock_device_coordinator.async_request_refresh.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_async_execute_command_skips_refresh_on_auth_error(
        self,
        entity: SabianaHvacClimateEntity,
        mock_device_coordinator: Mock,
    ) -> None:
        """On auth failure we neither write state nor ask for a refresh."""
        with patch(
            "custom_components.sabiana_hvac.climate.api.async_send_command",
            side_effect=SabianaApiAuthError("Auth failed"),
        ):
            entity.async_write_ha_state = Mock()
            await entity._async_execute_command()
            entity.async_write_ha_state.assert_not_called()
            mock_device_coordinator.async_request_refresh.assert_not_called()

    @pytest.mark.asyncio
    async def test_async_execute_command_skips_refresh_on_client_error(
        self,
        entity: SabianaHvacClimateEntity,
        mock_device_coordinator: Mock,
    ) -> None:
        """On API error we neither write state nor ask for a refresh."""
        with patch(
            "custom_components.sabiana_hvac.climate.api.async_send_command",
            side_effect=SabianaApiClientError("API error"),
        ):
            entity.async_write_ha_state = Mock()
            await entity._async_execute_command()
            entity.async_write_ha_state.assert_not_called()
            mock_device_coordinator.async_request_refresh.assert_not_called()

    @pytest.mark.asyncio
    async def test_async_execute_command_skips_refresh_on_request_error(
        self,
        entity: SabianaHvacClimateEntity,
        mock_device_coordinator: Mock,
    ) -> None:
        """Network errors are swallowed and skip the refresh."""
        with patch(
            "custom_components.sabiana_hvac.climate.api.async_send_command",
            side_effect=httpx.RequestError("Connection error"),
        ):
            entity.async_write_ha_state = Mock()
            await entity._async_execute_command()
            entity.async_write_ha_state.assert_not_called()
            mock_device_coordinator.async_request_refresh.assert_not_called()


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
