# Copyright (c) 2026 Edoardo Mistretta

"""Tests for the Sabiana Token Coordinator."""

import base64
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.helpers.update_coordinator import UpdateFailed

from custom_components.sabiana_hvac import api
from custom_components.sabiana_hvac.const import (
    CONF_LONG_JWT,
    CONF_LONG_JWT_EXPIRE_AT,
    CONF_SHORT_JWT,
    CONF_SHORT_JWT_EXPIRE_AT,
)
from custom_components.sabiana_hvac.coordinator import (
    SabianaDeviceCoordinator,
    SabianaTokenCoordinator,
)
from custom_components.sabiana_hvac.models import (
    JWT,
    SabianaDevice,
    SabianaDeviceList,
)
from custom_components.sabiana_hvac.websocket import (
    WebSocketConnectionEvent,
    WebSocketDeviceUpdate,
    WebSocketStatusEvent,
)

NEW_SHORT_JWT_VALUE = "new_short"
NEW_LONG_JWT_VALUE = "new_long"
NEW_SHORT_JWT_RENEWED_VALUE = "new_short_token"


@pytest.fixture
def mock_hass() -> Mock:
    """Create a mock Home Assistant instance."""
    hass = Mock()
    hass.config_entries = Mock()
    hass.config_entries.async_update_entry = Mock()
    return hass


@pytest.fixture
def mock_session() -> Mock:
    """Create a mock HTTP session."""
    return Mock(spec=httpx.AsyncClient)


@pytest.fixture
def sample_short_jwt_token() -> str:
    """Create a sample short JWT token for testing."""
    exp_timestamp = int(datetime.now(UTC).timestamp()) + 3600
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"exp": exp_timestamp, "sub": "test"}

    header_encoded = (
        base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    )
    payload_encoded = (
        base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    )
    return f"{header_encoded}.{payload_encoded}.signature"


@pytest.fixture
def sample_long_jwt_token() -> str:
    """Create a sample long JWT token for testing."""
    exp_timestamp = int(datetime.now(UTC).timestamp()) + 86400 * 30
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"exp": exp_timestamp, "sub": "test"}

    header_encoded = (
        base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    )
    payload_encoded = (
        base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    )
    return f"{header_encoded}.{payload_encoded}.signature"


@pytest.fixture
def config_entry_data(
    sample_short_jwt_token: str,
    sample_long_jwt_token: str,
) -> dict[str, Any]:
    """Create config entry data for testing."""
    now = datetime.now(UTC)
    return {
        CONF_EMAIL: "test@example.com",
        CONF_PASSWORD: "password123",
        CONF_SHORT_JWT: sample_short_jwt_token,
        CONF_SHORT_JWT_EXPIRE_AT: int((now + timedelta(hours=1)).timestamp()),
        CONF_LONG_JWT: sample_long_jwt_token,
        CONF_LONG_JWT_EXPIRE_AT: int((now + timedelta(days=30)).timestamp()),
    }


@pytest.fixture
def mock_config_entry(config_entry_data: dict[str, Any]) -> Mock:
    """Create a mock config entry for testing."""
    entry = Mock()
    entry.data = config_entry_data
    entry.entry_id = "test_entry_id"
    return entry


class TestSabianaTokenCoordinatorInit:
    """Tests for SabianaTokenCoordinator initialization."""

    def test_init_sets_session_and_config_entry(
        self,
        mock_hass: Mock,
        mock_session: Mock,
        mock_config_entry: Mock,
    ) -> None:
        """Test that init sets session and config entry correctly."""
        coordinator = SabianaTokenCoordinator(
            mock_hass,
            mock_session,
            mock_config_entry,
        )
        assert coordinator.session == mock_session
        assert coordinator.config_entry == mock_config_entry
        assert coordinator.data == mock_config_entry.data[CONF_SHORT_JWT]

    def test_init_sets_update_interval(
        self,
        mock_hass: Mock,
        mock_session: Mock,
        mock_config_entry: Mock,
    ) -> None:
        """Test that init sets update interval correctly."""
        coordinator = SabianaTokenCoordinator(
            mock_hass,
            mock_session,
            mock_config_entry,
        )
        assert coordinator.update_interval == timedelta(seconds=60)


class TestSabianaTokenCoordinatorShortJwt:
    """Tests for short_jwt property."""

    def test_short_jwt_returns_jwt_from_config_entry(
        self,
        mock_hass: Mock,
        mock_session: Mock,
        mock_config_entry: Mock,
        sample_short_jwt_token: str,
    ) -> None:
        """Test that short_jwt returns JWT from config entry."""
        coordinator = SabianaTokenCoordinator(
            mock_hass,
            mock_session,
            mock_config_entry,
        )
        jwt = coordinator.short_jwt
        assert isinstance(jwt, JWT)
        assert jwt.token == sample_short_jwt_token


class TestSabianaTokenCoordinatorLongJwt:
    """Tests for long_jwt property."""

    def test_long_jwt_returns_jwt_from_config_entry(
        self,
        mock_hass: Mock,
        mock_session: Mock,
        mock_config_entry: Mock,
        sample_long_jwt_token: str,
    ) -> None:
        """Test that long_jwt returns JWT from config entry."""
        coordinator = SabianaTokenCoordinator(
            mock_hass,
            mock_session,
            mock_config_entry,
        )
        jwt = coordinator.long_jwt
        assert isinstance(jwt, JWT)
        assert jwt.token == sample_long_jwt_token


class TestSabianaTokenCoordinatorAsyncUpdateData:
    """Tests for _async_update_data method."""

    @pytest.mark.asyncio
    async def test_async_update_data_returns_token_when_tokens_valid(
        self,
        mock_hass: Mock,
        mock_session: Mock,
        mock_config_entry: Mock,
        sample_short_jwt_token: str,
    ) -> None:
        """Test that _async_update_data returns token when tokens are valid."""
        coordinator = SabianaTokenCoordinator(
            mock_hass,
            mock_session,
            mock_config_entry,
        )
        result = await coordinator._async_update_data()
        assert result == sample_short_jwt_token

    @pytest.mark.asyncio
    async def test_async_update_data_refreshes_when_short_jwt_expired(
        self,
        mock_hass: Mock,
        mock_session: Mock,
        mock_config_entry: Mock,
    ) -> None:
        """Test that _async_update_data refreshes when short JWT is expired."""
        now = datetime.now(UTC)
        mock_config_entry.data[CONF_SHORT_JWT_EXPIRE_AT] = int(
            (now - timedelta(seconds=1)).timestamp(),
        )
        new_short_jwt = JWT(
            token=NEW_SHORT_JWT_RENEWED_VALUE,
            expire_at=now + timedelta(hours=1),
        )
        with patch(
            "custom_components.sabiana_hvac.coordinator.api.async_renew_jwt",
            return_value=new_short_jwt,
        ):
            coordinator = SabianaTokenCoordinator(
                mock_hass,
                mock_session,
                mock_config_entry,
            )
            result = await coordinator._async_update_data()
            assert result == NEW_SHORT_JWT_RENEWED_VALUE
            mock_hass.config_entries.async_update_entry.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_update_data_performs_reauth_when_long_jwt_expired(
        self,
        mock_hass: Mock,
        mock_session: Mock,
        mock_config_entry: Mock,
    ) -> None:
        """Test that _async_update_data performs reauth when long JWT is expired."""
        now = datetime.now(UTC)
        mock_config_entry.data[CONF_LONG_JWT_EXPIRE_AT] = int(
            (now - timedelta(seconds=1)).timestamp(),
        )
        new_short_jwt = JWT(
            token=NEW_SHORT_JWT_VALUE,
            expire_at=now + timedelta(hours=1),
        )
        new_long_jwt = JWT(
            token=NEW_LONG_JWT_VALUE,
            expire_at=now + timedelta(days=30),
        )
        with patch(
            "custom_components.sabiana_hvac.coordinator.api.async_authenticate",
            return_value=(new_short_jwt, new_long_jwt),
        ):
            coordinator = SabianaTokenCoordinator(
                mock_hass,
                mock_session,
                mock_config_entry,
            )
            result = await coordinator._async_update_data()
            assert result == NEW_SHORT_JWT_VALUE
            mock_hass.config_entries.async_update_entry.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_update_data_performs_reauth_on_renew_auth_error(
        self,
        mock_hass: Mock,
        mock_session: Mock,
        mock_config_entry: Mock,
    ) -> None:
        """Test that _async_update_data performs reauth on renew auth error."""
        now = datetime.now(UTC)
        mock_config_entry.data[CONF_SHORT_JWT_EXPIRE_AT] = int(
            (now - timedelta(seconds=1)).timestamp(),
        )
        new_short_jwt = JWT(
            token=NEW_SHORT_JWT_VALUE,
            expire_at=now + timedelta(hours=1),
        )
        new_long_jwt = JWT(
            token=NEW_LONG_JWT_VALUE,
            expire_at=now + timedelta(days=30),
        )
        error_message = "Auth failed"
        with (
            patch(
                "custom_components.sabiana_hvac.coordinator.api.async_renew_jwt",
                side_effect=api.SabianaApiAuthError(error_message),
            ),
            patch(
                "custom_components.sabiana_hvac.coordinator.api.async_authenticate",
                return_value=(new_short_jwt, new_long_jwt),
            ),
        ):
            coordinator = SabianaTokenCoordinator(
                mock_hass,
                mock_session,
                mock_config_entry,
            )
            result = await coordinator._async_update_data()
            assert result == NEW_SHORT_JWT_VALUE
            mock_hass.config_entries.async_update_entry.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_update_data_raises_update_failed_on_renew_client_error(
        self,
        mock_hass: Mock,
        mock_session: Mock,
        mock_config_entry: Mock,
    ) -> None:
        """Test that _async_update_data raises UpdateFailed on renew client error."""
        now = datetime.now(UTC)
        mock_config_entry.data[CONF_SHORT_JWT_EXPIRE_AT] = int(
            (now - timedelta(seconds=1)).timestamp(),
        )
        error_message = "API error"
        with patch(
            "custom_components.sabiana_hvac.coordinator.api.async_renew_jwt",
            side_effect=api.SabianaApiClientError(error_message),
        ):
            coordinator = SabianaTokenCoordinator(
                mock_hass,
                mock_session,
                mock_config_entry,
            )
            with pytest.raises(UpdateFailed, match=error_message):
                await coordinator._async_update_data()

    @pytest.mark.asyncio
    async def test_async_update_data_raises_update_failed_on_renew_request_error(
        self,
        mock_hass: Mock,
        mock_session: Mock,
        mock_config_entry: Mock,
    ) -> None:
        """Test that _async_update_data raises UpdateFailed on renew request error."""
        now = datetime.now(UTC)
        mock_config_entry.data[CONF_SHORT_JWT_EXPIRE_AT] = int(
            (now - timedelta(seconds=1)).timestamp(),
        )
        error_message = "Connection error"
        with patch(
            "custom_components.sabiana_hvac.coordinator.api.async_renew_jwt",
            side_effect=httpx.RequestError(error_message),
        ):
            coordinator = SabianaTokenCoordinator(
                mock_hass,
                mock_session,
                mock_config_entry,
            )
            with pytest.raises(UpdateFailed, match=error_message):
                await coordinator._async_update_data()


class TestSabianaTokenCoordinatorAsyncReauth:
    """Tests for _async_reauth method."""

    @pytest.mark.asyncio
    async def test_async_reauth_returns_jwt_tokens_on_success(
        self,
        mock_hass: Mock,
        mock_session: Mock,
        mock_config_entry: Mock,
    ) -> None:
        """Test that _async_reauth returns JWT tokens on success."""
        new_short_jwt = JWT(
            token=NEW_SHORT_JWT_VALUE,
            expire_at=datetime.now(UTC) + timedelta(hours=1),
        )
        new_long_jwt = JWT(
            token=NEW_LONG_JWT_VALUE,
            expire_at=datetime.now(UTC) + timedelta(days=30),
        )
        with patch(
            "custom_components.sabiana_hvac.coordinator.api.async_authenticate",
            return_value=(new_short_jwt, new_long_jwt),
        ):
            coordinator = SabianaTokenCoordinator(
                mock_hass,
                mock_session,
                mock_config_entry,
            )
            short_jwt, long_jwt = await coordinator._async_reauth()
            assert short_jwt == new_short_jwt
            assert long_jwt == new_long_jwt

    @pytest.mark.asyncio
    async def test_async_reauth_raises_update_failed_when_email_missing(
        self,
        mock_hass: Mock,
        mock_session: Mock,
        mock_config_entry: Mock,
    ) -> None:
        """Test that _async_reauth raises UpdateFailed when email is missing."""
        mock_config_entry.data.pop(CONF_EMAIL)
        coordinator = SabianaTokenCoordinator(
            mock_hass,
            mock_session,
            mock_config_entry,
        )
        error_message = "Email or password not found"
        with pytest.raises(UpdateFailed, match=error_message):
            await coordinator._async_reauth()

    @pytest.mark.asyncio
    async def test_async_reauth_raises_update_failed_when_password_missing(
        self,
        mock_hass: Mock,
        mock_session: Mock,
        mock_config_entry: Mock,
    ) -> None:
        """Test that _async_reauth raises UpdateFailed when password is missing."""
        mock_config_entry.data.pop(CONF_PASSWORD)
        coordinator = SabianaTokenCoordinator(
            mock_hass,
            mock_session,
            mock_config_entry,
        )
        error_message = "Email or password not found"
        with pytest.raises(UpdateFailed, match=error_message):
            await coordinator._async_reauth()

    @pytest.mark.asyncio
    async def test_async_reauth_raises_update_failed_on_auth_error(
        self,
        mock_hass: Mock,
        mock_session: Mock,
        mock_config_entry: Mock,
    ) -> None:
        """Test that _async_reauth raises UpdateFailed on auth error."""
        error_message = "Invalid credentials"
        with patch(
            "custom_components.sabiana_hvac.coordinator.api.async_authenticate",
            side_effect=api.SabianaApiAuthError(error_message),
        ):
            coordinator = SabianaTokenCoordinator(
                mock_hass,
                mock_session,
                mock_config_entry,
            )
            with pytest.raises(UpdateFailed, match=error_message):
                await coordinator._async_reauth()

    @pytest.mark.asyncio
    async def test_async_reauth_raises_update_failed_on_client_error(
        self,
        mock_hass: Mock,
        mock_session: Mock,
        mock_config_entry: Mock,
    ) -> None:
        """Test that _async_reauth raises UpdateFailed on client error."""
        error_message = "API error"
        with patch(
            "custom_components.sabiana_hvac.coordinator.api.async_authenticate",
            side_effect=api.SabianaApiClientError(error_message),
        ):
            coordinator = SabianaTokenCoordinator(
                mock_hass,
                mock_session,
                mock_config_entry,
            )
            with pytest.raises(UpdateFailed, match=error_message):
                await coordinator._async_reauth()

    @pytest.mark.asyncio
    async def test_async_reauth_raises_update_failed_on_request_error(
        self,
        mock_hass: Mock,
        mock_session: Mock,
        mock_config_entry: Mock,
    ) -> None:
        """Test that _async_reauth raises UpdateFailed on request error."""
        error_message = "Connection error"
        with patch(
            "custom_components.sabiana_hvac.coordinator.api.async_authenticate",
            side_effect=httpx.RequestError(error_message),
        ):
            coordinator = SabianaTokenCoordinator(
                mock_hass,
                mock_session,
                mock_config_entry,
            )
            with pytest.raises(UpdateFailed, match=error_message):
                await coordinator._async_reauth()


class TestSabianaTokenCoordinatorUpdateTokens:
    """Tests for _update_tokens method."""

    def test_update_tokens_updates_short_jwt_only(
        self,
        mock_hass: Mock,
        mock_session: Mock,
        mock_config_entry: Mock,
    ) -> None:
        """Test that _update_tokens updates short JWT only."""
        new_short_jwt = JWT(
            token=NEW_SHORT_JWT_VALUE,
            expire_at=datetime.now(UTC) + timedelta(hours=1),
        )
        original_long_jwt = mock_config_entry.data[CONF_LONG_JWT]
        coordinator = SabianaTokenCoordinator(
            mock_hass,
            mock_session,
            mock_config_entry,
        )
        coordinator._update_tokens(new_short_jwt)
        mock_hass.config_entries.async_update_entry.assert_called_once()
        call_args = mock_hass.config_entries.async_update_entry.call_args
        assert call_args[1]["data"][CONF_SHORT_JWT] == NEW_SHORT_JWT_VALUE
        assert call_args[1]["data"][CONF_LONG_JWT] == original_long_jwt
        assert coordinator.data == NEW_SHORT_JWT_VALUE

    def test_update_tokens_updates_both_jwts_when_long_provided(
        self,
        mock_hass: Mock,
        mock_session: Mock,
        mock_config_entry: Mock,
    ) -> None:
        """Test that _update_tokens updates both JWTs when long is provided."""
        new_short_jwt = JWT(
            token=NEW_SHORT_JWT_VALUE,
            expire_at=datetime.now(UTC) + timedelta(hours=1),
        )
        new_long_jwt = JWT(
            token=NEW_LONG_JWT_VALUE,
            expire_at=datetime.now(UTC) + timedelta(days=30),
        )
        coordinator = SabianaTokenCoordinator(
            mock_hass,
            mock_session,
            mock_config_entry,
        )
        coordinator._update_tokens(new_short_jwt, new_long_jwt)
        mock_hass.config_entries.async_update_entry.assert_called_once()
        call_args = mock_hass.config_entries.async_update_entry.call_args
        assert call_args[1]["data"][CONF_SHORT_JWT] == NEW_SHORT_JWT_VALUE
        assert call_args[1]["data"][CONF_LONG_JWT] == NEW_LONG_JWT_VALUE
        assert coordinator.data == NEW_SHORT_JWT_VALUE

    def test_update_tokens_preserves_existing_config_data(
        self,
        mock_hass: Mock,
        mock_session: Mock,
        mock_config_entry: Mock,
    ) -> None:
        """Test that _update_tokens preserves existing config data."""
        original_email = mock_config_entry.data[CONF_EMAIL]
        new_short_jwt = JWT(
            token=NEW_SHORT_JWT_VALUE,
            expire_at=datetime.now(UTC) + timedelta(hours=1),
        )
        coordinator = SabianaTokenCoordinator(
            mock_hass,
            mock_session,
            mock_config_entry,
        )
        coordinator._update_tokens(new_short_jwt)
        call_args = mock_hass.config_entries.async_update_entry.call_args
        assert call_args[1]["data"][CONF_EMAIL] == original_email


# ---------------------------------------------------------------------------
# Long JWT rotation (app: checkResponse)
# ---------------------------------------------------------------------------


class TestSabianaTokenCoordinatorStoreRotatedLongJwt:
    """Tests for store_rotated_long_jwt."""

    def test_stores_rotated_token(
        self, mock_hass: Mock, mock_session: Mock, mock_config_entry: Mock
    ) -> None:
        """A new long JWT is saved with its expiry, other data kept."""
        coordinator = SabianaTokenCoordinator(
            mock_hass, mock_session, mock_config_entry
        )
        exp = int(datetime.now(UTC).timestamp()) + 86400 * 90
        token = _jwt(exp)

        coordinator.store_rotated_long_jwt(token)

        data = mock_hass.config_entries.async_update_entry.call_args.kwargs["data"]
        assert data[CONF_LONG_JWT] == token
        assert data[CONF_LONG_JWT_EXPIRE_AT] == exp
        assert data[CONF_SHORT_JWT] == mock_config_entry.data[CONF_SHORT_JWT]
        assert data[CONF_EMAIL] == mock_config_entry.data[CONF_EMAIL]

    def test_ignores_current_token(
        self, mock_hass: Mock, mock_session: Mock, mock_config_entry: Mock
    ) -> None:
        """The token already stored is not written again."""
        coordinator = SabianaTokenCoordinator(
            mock_hass, mock_session, mock_config_entry
        )
        coordinator.store_rotated_long_jwt(mock_config_entry.data[CONF_LONG_JWT])
        mock_hass.config_entries.async_update_entry.assert_not_called()

    def test_ignores_token_without_expiry(
        self, mock_hass: Mock, mock_session: Mock, mock_config_entry: Mock
    ) -> None:
        """A token whose exp cannot be read keeps the current long JWT."""
        coordinator = SabianaTokenCoordinator(
            mock_hass, mock_session, mock_config_entry
        )
        coordinator.store_rotated_long_jwt("not-a-jwt-at-all")
        mock_hass.config_entries.async_update_entry.assert_not_called()


# ---------------------------------------------------------------------------
# Device coordinator (getDeviceForUserV2 + Socket.IO events)
# ---------------------------------------------------------------------------

FRAME_500D_WORDS = (
    "500d",
    "002b",
    "0400",
    "01c4",
    "0001",
    "0124",
    "00f5",
    "0104",
    "00dc",
    "c800",
    "c800",
    "0000",
    "0000",
    "467b",
    "002b",
    "0000",
    "0004",
    "0000",
    "0000",
    "0000",
)
FRAME_500D_OFF = "".join(FRAME_500D_WORDS)
# Same unit switched on (word 4 bit 0 set) in heating (word 3 = 0401).
FRAME_500D_ON = FRAME_500D_OFF[:8] + "040101c5" + FRAME_500D_OFF[16:]
STATUS_RSSI = -80


def _jwt(exp: int) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode().rstrip("=")
    payload = (
        base64.urlsafe_b64encode(json.dumps({"exp": exp, "sub": "renew"}).encode())
        .decode()
        .rstrip("=")
    )
    return f"{header}.{payload}.signature"


def _device(device_id: str = "swm-1", **kwargs: object) -> SabianaDevice:
    return api.parse_device(
        {
            "idDevice": device_id,
            "deviceStateModelType": "cvp",
            "lastData": FRAME_500D_OFF,
            "connectionUp": True,
            **kwargs,
        }
    )


def _device_list(
    *devices: SabianaDevice, token: str | None = None
) -> SabianaDeviceList:
    return SabianaDeviceList(
        devices={d.id: d for d in devices},
        last_fw={"cvp": "0.45"},
        rotated_token=token,
    )


@pytest.fixture
def token_coordinator() -> Mock:
    """Create a mock token coordinator."""
    coordinator = Mock()
    coordinator.async_request_refresh = AsyncMock()
    coordinator.short_jwt = JWT(token="short-token", expire_at=datetime.now(UTC))  # noqa: S106
    return coordinator


@pytest.fixture
def websocket_manager() -> Mock:
    """Create a mock WebSocket manager that records registered callbacks."""
    manager = Mock()
    manager.connected = False
    return manager


@pytest.fixture
def device_coordinator(
    mock_hass: Mock,
    mock_session: Mock,
    mock_config_entry: Mock,
    token_coordinator: Mock,
    websocket_manager: Mock,
) -> SabianaDeviceCoordinator:
    """Create a device coordinator whose updates are applied synchronously."""
    mock_hass.config_entries.async_schedule_reload = Mock()
    coordinator = SabianaDeviceCoordinator(
        mock_hass,
        mock_session,
        token_coordinator,
        mock_config_entry,
        websocket_manager=websocket_manager,
    )

    def set_data(data: dict[str, SabianaDevice]) -> None:
        coordinator.data = data

    coordinator.async_set_updated_data = Mock(side_effect=set_data)
    return coordinator


class TestSabianaDeviceCoordinatorUpdate:
    """Tests for the REST read of the device list."""

    @pytest.mark.asyncio
    async def test_returns_device_records(
        self, device_coordinator: SabianaDeviceCoordinator, token_coordinator: Mock
    ) -> None:
        """The data is the device list keyed by idDevice; lastFw is kept."""
        device = _device()
        with patch.object(
            api, "async_get_devices", AsyncMock(return_value=_device_list(device))
        ) as get_devices:
            data = await device_coordinator._async_update_data()

        token_coordinator.async_request_refresh.assert_awaited_once()
        assert get_devices.await_args.args[1] == "short-token"
        assert data == {"swm-1": device}
        assert device_coordinator.last_fw == {"cvp": "0.45"}
        assert device_coordinator.device_ids == {"swm-1"}

    @pytest.mark.asyncio
    async def test_stores_rotated_token(
        self, device_coordinator: SabianaDeviceCoordinator, token_coordinator: Mock
    ) -> None:
        """A token in the envelope is handed to the token coordinator."""
        with patch.object(
            api,
            "async_get_devices",
            AsyncMock(return_value=_device_list(_device(), token="rotated")),  # noqa: S106
        ):
            await device_coordinator._async_update_data()
        token_coordinator.store_rotated_long_jwt.assert_called_once_with("rotated")

    @pytest.mark.asyncio
    async def test_reloads_when_device_set_changes(
        self, device_coordinator: SabianaDeviceCoordinator, mock_hass: Mock
    ) -> None:
        """A device added to the account triggers a reload, not the first read."""
        reload = mock_hass.config_entries.async_schedule_reload
        responses = [
            _device_list(_device("swm-1")),
            _device_list(_device("swm-1", deviceName="renamed")),
            _device_list(_device("swm-1"), _device("swm-2")),
        ]
        with patch.object(api, "async_get_devices", AsyncMock(side_effect=responses)):
            await device_coordinator._async_update_data()
            await device_coordinator._async_update_data()
            reload.assert_not_called()
            await device_coordinator._async_update_data()

        reload.assert_called_once_with("test_entry_id")
        assert device_coordinator.device_ids == {"swm-1", "swm-2"}

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "error",
        [
            api.SabianaApiAuthError("auth"),
            api.SabianaApiClientError("api"),
            httpx.ConnectError("down"),
        ],
    )
    async def test_errors_raise_update_failed(
        self, device_coordinator: SabianaDeviceCoordinator, error: Exception
    ) -> None:
        """API and network errors become UpdateFailed."""
        with (
            patch.object(api, "async_get_devices", AsyncMock(side_effect=error)),
            pytest.raises(UpdateFailed),
        ):
            await device_coordinator._async_update_data()


class TestSabianaDeviceCoordinatorWebSocketEvents:
    """Socket.IO events applied to the device records."""

    def test_no_polling(self, device_coordinator: SabianaDeviceCoordinator) -> None:
        """The app never reads the list on a timer."""
        assert device_coordinator.update_interval is None

    def test_connection_status_updates_entities(
        self, device_coordinator: SabianaDeviceCoordinator
    ) -> None:
        """Socket up/down changes availability: listeners are notified."""
        with patch.object(device_coordinator, "async_update_listeners") as update:
            device_coordinator._handle_ws_connection_status(connected=False)
            device_coordinator._handle_ws_connection_status(connected=True)
        assert update.call_count == 2  # noqa: PLR2004
        assert device_coordinator.update_interval is None

    def test_realtime_connected_follows_the_socket(
        self,
        device_coordinator: SabianaDeviceCoordinator,
        websocket_manager: Mock,
    ) -> None:
        """realtime_connected mirrors the WebSocket manager."""
        websocket_manager.connected = True
        assert device_coordinator.realtime_connected is True
        websocket_manager.connected = False
        assert device_coordinator.realtime_connected is False

    @pytest.mark.usefixtures("device_coordinator")
    def test_registers_all_callbacks(self, websocket_manager: Mock) -> None:
        """data, connEvents, status, appMsg refresh and connection status."""
        websocket_manager.register_device_update_callback.assert_called_once()
        websocket_manager.register_connection_event_callback.assert_called_once()
        websocket_manager.register_status_callback.assert_called_once()
        websocket_manager.register_refresh_callback.assert_called_once()
        websocket_manager.register_connection_status_callback.assert_called_once()

    def test_data_event_decodes_and_forces_online(
        self, device_coordinator: SabianaDeviceCoordinator
    ) -> None:
        """A frame replaces lastData and state and sets connectionUp."""
        device_coordinator.data = {"swm-1": _device(connectionUp=False)}
        device_coordinator._handle_ws_data(
            WebSocketDeviceUpdate(device_id="swm-1", data=FRAME_500D_ON)
        )
        device = device_coordinator.data["swm-1"]
        assert device.last_data == FRAME_500D_ON
        assert device.connection_up is True
        assert device.state is not None
        assert (device.state.on, device.state.mode) == (True, 1)
        assert device.controllable is True

    def test_unchanged_frame_on_online_device_is_ignored(
        self, device_coordinator: SabianaDeviceCoordinator
    ) -> None:
        """Same frame, already online: no listener update."""
        device_coordinator.data = {"swm-1": _device()}
        device_coordinator._handle_ws_data(
            WebSocketDeviceUpdate(device_id="swm-1", data=FRAME_500D_OFF)
        )
        device_coordinator.async_set_updated_data.assert_not_called()

    def test_unknown_device_is_ignored(
        self, device_coordinator: SabianaDeviceCoordinator
    ) -> None:
        """Events for devices not in the list are dropped."""
        device_coordinator.data = {"swm-1": _device()}
        device_coordinator._handle_ws_data(
            WebSocketDeviceUpdate(device_id="other", data=FRAME_500D_ON)
        )
        device_coordinator.async_set_updated_data.assert_not_called()

    def test_invalid_frame_keeps_state_but_marks_invalid(
        self, device_coordinator: SabianaDeviceCoordinator
    ) -> None:
        """A DATA-ERROR frame blocks control but keeps the last decoding."""
        previous = _device()
        device_coordinator.data = {"swm-1": previous}
        device_coordinator._handle_ws_data(
            WebSocketDeviceUpdate(device_id="swm-1", data="999999")
        )
        device = device_coordinator.data["swm-1"]
        assert device.state == previous.state
        assert device.data_valid is False
        assert device.controllable is False

    def test_conn_event_toggles_connection(
        self, device_coordinator: SabianaDeviceCoordinator
    ) -> None:
        """A connEvents event sets connectionUp; a repeated value is a no-op."""
        device_coordinator.data = {"swm-1": _device()}
        device_coordinator._handle_ws_conn_event(
            WebSocketConnectionEvent(device_id="swm-1", connected=False)
        )
        assert device_coordinator.data["swm-1"].connection_up is False

        device_coordinator.async_set_updated_data.reset_mock()
        device_coordinator._handle_ws_conn_event(
            WebSocketConnectionEvent(device_id="swm-1", connected=False)
        )
        device_coordinator.async_set_updated_data.assert_not_called()

    def test_status_event_updates_firmware_and_rssi(
        self, device_coordinator: SabianaDeviceCoordinator
    ) -> None:
        """A status event sets deviceStateFw and deviceWiFiRSSI."""
        device_coordinator.data = {"swm-1": _device()}
        device_coordinator._handle_ws_status(
            WebSocketStatusEvent(
                device_id="swm-1", wifi_fw="1.30", wifi_rssi=STATUS_RSSI
            )
        )
        device = device_coordinator.data["swm-1"]
        assert (device.wifi_fw, device.wifi_rssi) == ("1.30", STATUS_RSSI)
        assert (device.wifi_signal, device.wifi_weak) == (2, True)

    @pytest.mark.asyncio
    async def test_shutdown_unregisters_callbacks(
        self, device_coordinator: SabianaDeviceCoordinator, websocket_manager: Mock
    ) -> None:
        """Every registered callback is removed on shutdown."""
        unregister = websocket_manager.register_status_callback.return_value
        with patch(
            "homeassistant.helpers.update_coordinator.DataUpdateCoordinator.async_shutdown",
            AsyncMock(),
        ):
            await device_coordinator.async_shutdown()
        unregister.assert_called_once()


class TestSabianaTokenCoordinatorLogging:
    """Secrets stay out of the logs."""

    @pytest.mark.asyncio
    async def test_debug_log_redacts_password_and_tokens(
        self,
        mock_hass: Mock,
        mock_session: Mock,
        mock_config_entry: Mock,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The config entry dump hides password and JWTs, keeps the rest."""
        caplog.set_level(logging.DEBUG)
        coordinator = SabianaTokenCoordinator(
            mock_hass, mock_session, mock_config_entry
        )
        await coordinator._async_update_data()

        data = mock_config_entry.data
        assert "Config entry data" in caplog.text
        for secret in (data[CONF_PASSWORD], data[CONF_SHORT_JWT], data[CONF_LONG_JWT]):
            assert secret not in caplog.text
        assert data[CONF_EMAIL] in caplog.text
        assert "**REDACTED**" in caplog.text
