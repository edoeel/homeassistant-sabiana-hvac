from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.helpers.update_coordinator import UpdateFailed

from custom_components.sabiana_hvac import api
from custom_components.sabiana_hvac.coordinator import SabianaTokenCoordinator
from custom_components.sabiana_hvac.const import (
    CONF_LONG_JWT,
    CONF_LONG_JWT_EXPIRE_AT,
    CONF_SHORT_JWT,
    CONF_SHORT_JWT_EXPIRE_AT,
)
from custom_components.sabiana_hvac.models import JWT


@pytest.fixture
def mock_hass():
    hass = Mock()
    hass.config_entries = Mock()
    hass.config_entries.async_update_entry = AsyncMock()
    return hass


@pytest.fixture
def mock_session():
    return Mock(spec=httpx.AsyncClient)


@pytest.fixture
def sample_short_jwt_token():
    exp_timestamp = int(datetime.now(UTC).timestamp()) + 3600
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"exp": exp_timestamp, "sub": "test"}
    import base64
    import json

    header_encoded = (
        base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    )
    payload_encoded = (
        base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    )
    return f"{header_encoded}.{payload_encoded}.signature"


@pytest.fixture
def sample_long_jwt_token():
    exp_timestamp = int(datetime.now(UTC).timestamp()) + 86400 * 30
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"exp": exp_timestamp, "sub": "test"}
    import base64
    import json

    header_encoded = (
        base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    )
    payload_encoded = (
        base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    )
    return f"{header_encoded}.{payload_encoded}.signature"


@pytest.fixture
def config_entry_data(sample_short_jwt_token, sample_long_jwt_token):
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
def mock_config_entry(config_entry_data):
    entry = Mock()
    entry.data = config_entry_data
    entry.entry_id = "test_entry_id"
    return entry


class TestSabianaTokenCoordinatorInit:
    def test_init_sets_session_and_config_entry(
        self, mock_hass, mock_session, mock_config_entry
    ):
        coordinator = SabianaTokenCoordinator(
            mock_hass, mock_session, mock_config_entry
        )
        assert coordinator.session == mock_session
        assert coordinator.config_entry == mock_config_entry
        assert coordinator.data == mock_config_entry.data[CONF_SHORT_JWT]

    def test_init_sets_update_interval(self, mock_hass, mock_session, mock_config_entry):
        coordinator = SabianaTokenCoordinator(
            mock_hass, mock_session, mock_config_entry
        )
        assert coordinator.update_interval == timedelta(seconds=60)


class TestSabianaTokenCoordinatorShortJwt:
    def test_short_jwt_returns_jwt_from_config_entry(
        self, mock_hass, mock_session, mock_config_entry, sample_short_jwt_token
    ):
        coordinator = SabianaTokenCoordinator(
            mock_hass, mock_session, mock_config_entry
        )
        jwt = coordinator.short_jwt
        assert isinstance(jwt, JWT)
        assert jwt.token == sample_short_jwt_token


class TestSabianaTokenCoordinatorLongJwt:
    def test_long_jwt_returns_jwt_from_config_entry(
        self, mock_hass, mock_session, mock_config_entry, sample_long_jwt_token
    ):
        coordinator = SabianaTokenCoordinator(
            mock_hass, mock_session, mock_config_entry
        )
        jwt = coordinator.long_jwt
        assert isinstance(jwt, JWT)
        assert jwt.token == sample_long_jwt_token


class TestSabianaTokenCoordinatorAsyncUpdateData:
    @pytest.mark.asyncio
    async def test_async_update_data_returns_token_when_tokens_valid(
        self, mock_hass, mock_session, mock_config_entry, sample_short_jwt_token
    ):
        coordinator = SabianaTokenCoordinator(
            mock_hass, mock_session, mock_config_entry
        )
        result = await coordinator._async_update_data()
        assert result == sample_short_jwt_token

    @pytest.mark.asyncio
    async def test_async_update_data_refreshes_when_short_jwt_expired(
        self, mock_hass, mock_session, mock_config_entry, sample_short_jwt_token
    ):
        now = datetime.now(UTC)
        mock_config_entry.data[CONF_SHORT_JWT_EXPIRE_AT] = int(
            (now - timedelta(seconds=1)).timestamp()
        )
        new_short_jwt = JWT(
            token="new_short_token",
            expire_at=now + timedelta(hours=1),
        )
        with patch(
            "custom_components.sabiana_hvac.coordinator.api.async_renew_jwt",
            return_value=new_short_jwt,
        ):
            coordinator = SabianaTokenCoordinator(
                mock_hass, mock_session, mock_config_entry
            )
            result = await coordinator._async_update_data()
            assert result == "new_short_token"
            mock_hass.config_entries.async_update_entry.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_update_data_performs_reauth_when_long_jwt_expired(
        self, mock_hass, mock_session, mock_config_entry
    ):
        now = datetime.now(UTC)
        mock_config_entry.data[CONF_LONG_JWT_EXPIRE_AT] = int(
            (now - timedelta(seconds=1)).timestamp()
        )
        new_short_jwt = JWT(token="new_short", expire_at=now + timedelta(hours=1))
        new_long_jwt = JWT(token="new_long", expire_at=now + timedelta(days=30))
        with patch(
            "custom_components.sabiana_hvac.coordinator.api.async_authenticate",
            return_value=(new_short_jwt, new_long_jwt),
        ):
            coordinator = SabianaTokenCoordinator(
                mock_hass, mock_session, mock_config_entry
            )
            result = await coordinator._async_update_data()
            assert result == "new_short"
            mock_hass.config_entries.async_update_entry.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_update_data_performs_reauth_on_renew_auth_error(
        self, mock_hass, mock_session, mock_config_entry, sample_short_jwt_token
    ):
        now = datetime.now(UTC)
        mock_config_entry.data[CONF_SHORT_JWT_EXPIRE_AT] = int(
            (now - timedelta(seconds=1)).timestamp()
        )
        new_short_jwt = JWT(token="new_short", expire_at=now + timedelta(hours=1))
        new_long_jwt = JWT(token="new_long", expire_at=now + timedelta(days=30))
        with patch(
            "custom_components.sabiana_hvac.coordinator.api.async_renew_jwt",
            side_effect=api.SabianaApiAuthError("Auth failed"),
        ), patch(
            "custom_components.sabiana_hvac.coordinator.api.async_authenticate",
            return_value=(new_short_jwt, new_long_jwt),
        ):
            coordinator = SabianaTokenCoordinator(
                mock_hass, mock_session, mock_config_entry
            )
            result = await coordinator._async_update_data()
            assert result == "new_short"
            mock_hass.config_entries.async_update_entry.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_update_data_raises_update_failed_on_renew_client_error(
        self, mock_hass, mock_session, mock_config_entry
    ):
        now = datetime.now(UTC)
        mock_config_entry.data[CONF_SHORT_JWT_EXPIRE_AT] = int(
            (now - timedelta(seconds=1)).timestamp()
        )
        with patch(
            "custom_components.sabiana_hvac.coordinator.api.async_renew_jwt",
            side_effect=api.SabianaApiClientError("API error"),
        ):
            coordinator = SabianaTokenCoordinator(
                mock_hass, mock_session, mock_config_entry
            )
            with pytest.raises(UpdateFailed, match="API error"):
                await coordinator._async_update_data()

    @pytest.mark.asyncio
    async def test_async_update_data_raises_update_failed_on_renew_request_error(
        self, mock_hass, mock_session, mock_config_entry
    ):
        now = datetime.now(UTC)
        mock_config_entry.data[CONF_SHORT_JWT_EXPIRE_AT] = int(
            (now - timedelta(seconds=1)).timestamp()
        )
        with patch(
            "custom_components.sabiana_hvac.coordinator.api.async_renew_jwt",
            side_effect=httpx.RequestError("Connection error"),
        ):
            coordinator = SabianaTokenCoordinator(
                mock_hass, mock_session, mock_config_entry
            )
            with pytest.raises(UpdateFailed, match="Connection error"):
                await coordinator._async_update_data()


class TestSabianaTokenCoordinatorAsyncReauth:
    @pytest.mark.asyncio
    async def test_async_reauth_returns_jwt_tokens_on_success(
        self, mock_hass, mock_session, mock_config_entry
    ):
        new_short_jwt = JWT(
            token="new_short", expire_at=datetime.now(UTC) + timedelta(hours=1)
        )
        new_long_jwt = JWT(
            token="new_long", expire_at=datetime.now(UTC) + timedelta(days=30)
        )
        with patch(
            "custom_components.sabiana_hvac.coordinator.api.async_authenticate",
            return_value=(new_short_jwt, new_long_jwt),
        ):
            coordinator = SabianaTokenCoordinator(
                mock_hass, mock_session, mock_config_entry
            )
            short_jwt, long_jwt = await coordinator._async_reauth()
            assert short_jwt == new_short_jwt
            assert long_jwt == new_long_jwt

    @pytest.mark.asyncio
    async def test_async_reauth_raises_update_failed_when_email_missing(
        self, mock_hass, mock_session, mock_config_entry
    ):
        mock_config_entry.data.pop(CONF_EMAIL)
        coordinator = SabianaTokenCoordinator(
            mock_hass, mock_session, mock_config_entry
        )
        with pytest.raises(UpdateFailed, match="Email or password not found"):
            await coordinator._async_reauth()

    @pytest.mark.asyncio
    async def test_async_reauth_raises_update_failed_when_password_missing(
        self, mock_hass, mock_session, mock_config_entry
    ):
        mock_config_entry.data.pop(CONF_PASSWORD)
        coordinator = SabianaTokenCoordinator(
            mock_hass, mock_session, mock_config_entry
        )
        with pytest.raises(UpdateFailed, match="Email or password not found"):
            await coordinator._async_reauth()

    @pytest.mark.asyncio
    async def test_async_reauth_raises_update_failed_on_auth_error(
        self, mock_hass, mock_session, mock_config_entry
    ):
        with patch(
            "custom_components.sabiana_hvac.coordinator.api.async_authenticate",
            side_effect=api.SabianaApiAuthError("Invalid credentials"),
        ):
            coordinator = SabianaTokenCoordinator(
                mock_hass, mock_session, mock_config_entry
            )
            with pytest.raises(UpdateFailed, match="Invalid credentials"):
                await coordinator._async_reauth()

    @pytest.mark.asyncio
    async def test_async_reauth_raises_update_failed_on_client_error(
        self, mock_hass, mock_session, mock_config_entry
    ):
        with patch(
            "custom_components.sabiana_hvac.coordinator.api.async_authenticate",
            side_effect=api.SabianaApiClientError("API error"),
        ):
            coordinator = SabianaTokenCoordinator(
                mock_hass, mock_session, mock_config_entry
            )
            with pytest.raises(UpdateFailed, match="API error"):
                await coordinator._async_reauth()

    @pytest.mark.asyncio
    async def test_async_reauth_raises_update_failed_on_request_error(
        self, mock_hass, mock_session, mock_config_entry
    ):
        with patch(
            "custom_components.sabiana_hvac.coordinator.api.async_authenticate",
            side_effect=httpx.RequestError("Connection error"),
        ):
            coordinator = SabianaTokenCoordinator(
                mock_hass, mock_session, mock_config_entry
            )
            with pytest.raises(UpdateFailed, match="Connection error"):
                await coordinator._async_reauth()


class TestSabianaTokenCoordinatorUpdateTokens:
    def test_update_tokens_updates_short_jwt_only(
        self, mock_hass, mock_session, mock_config_entry
    ):
        new_short_jwt = JWT(
            token="new_short", expire_at=datetime.now(UTC) + timedelta(hours=1)
        )
        original_long_jwt = mock_config_entry.data[CONF_LONG_JWT]
        coordinator = SabianaTokenCoordinator(
            mock_hass, mock_session, mock_config_entry
        )
        coordinator._update_tokens(new_short_jwt)
        mock_hass.config_entries.async_update_entry.assert_called_once()
        call_args = mock_hass.config_entries.async_update_entry.call_args
        assert call_args[1]["data"][CONF_SHORT_JWT] == "new_short"
        assert call_args[1]["data"][CONF_LONG_JWT] == original_long_jwt
        assert coordinator.data == "new_short"

    def test_update_tokens_updates_both_jwts_when_long_provided(
        self, mock_hass, mock_session, mock_config_entry
    ):
        new_short_jwt = JWT(
            token="new_short", expire_at=datetime.now(UTC) + timedelta(hours=1)
        )
        new_long_jwt = JWT(
            token="new_long", expire_at=datetime.now(UTC) + timedelta(days=30)
        )
        coordinator = SabianaTokenCoordinator(
            mock_hass, mock_session, mock_config_entry
        )
        coordinator._update_tokens(new_short_jwt, new_long_jwt)
        mock_hass.config_entries.async_update_entry.assert_called_once()
        call_args = mock_hass.config_entries.async_update_entry.call_args
        assert call_args[1]["data"][CONF_SHORT_JWT] == "new_short"
        assert call_args[1]["data"][CONF_LONG_JWT] == "new_long"
        assert coordinator.data == "new_short"

    def test_update_tokens_preserves_existing_config_data(
        self, mock_hass, mock_session, mock_config_entry
    ):
        original_email = mock_config_entry.data[CONF_EMAIL]
        new_short_jwt = JWT(
            token="new_short", expire_at=datetime.now(UTC) + timedelta(hours=1)
        )
        coordinator = SabianaTokenCoordinator(
            mock_hass, mock_session, mock_config_entry
        )
        coordinator._update_tokens(new_short_jwt)
        call_args = mock_hass.config_entries.async_update_entry.call_args
        assert call_args[1]["data"][CONF_EMAIL] == original_email

