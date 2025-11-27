"""Tests for the Sabiana Token Coordinator."""

import base64
import json
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
from custom_components.sabiana_hvac.coordinator import SabianaTokenCoordinator
from custom_components.sabiana_hvac.models import JWT

NEW_SHORT_JWT_VALUE = "new_short"
NEW_LONG_JWT_VALUE = "new_long"
NEW_SHORT_JWT_RENEWED_VALUE = "new_short_token"


@pytest.fixture
def mock_hass() -> Mock:
    """Create a mock Home Assistant instance."""
    hass = Mock()
    hass.config_entries = Mock()
    hass.config_entries.async_update_entry = AsyncMock()
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
