from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.data_entry_flow import FlowResultType

from custom_components.sabiana_hvac import api
from custom_components.sabiana_hvac.config_flow import SabianaHvacConfigFlow
from custom_components.sabiana_hvac.const import (
    CONF_LONG_JWT,
    CONF_LONG_JWT_EXPIRE_AT,
    CONF_SHORT_JWT,
    CONF_SHORT_JWT_EXPIRE_AT,
    DOMAIN,
    ERROR_API_ERROR,
    ERROR_CANNOT_CONNECT,
    ERROR_INVALID_AUTH,
    ERROR_TIMEOUT,
    ERROR_UNKNOWN,
)
from custom_components.sabiana_hvac.models import JWT


@pytest.fixture
def mock_hass():
    hass = Mock()
    return hass


@pytest.fixture
def flow(mock_hass):
    flow_instance = SabianaHvacConfigFlow()
    flow_instance.hass = mock_hass
    flow_instance.async_set_unique_id = AsyncMock()
    flow_instance._abort_if_unique_id_configured = Mock()
    flow_instance.async_create_entry = Mock(
        return_value={"type": FlowResultType.CREATE_ENTRY}
    )
    flow_instance.async_show_form = Mock(
        return_value={"type": FlowResultType.FORM}
    )
    return flow_instance


@pytest.fixture
def sample_jwt_tokens():
    now = datetime.now(UTC)
    short_jwt = JWT(
        token="short_jwt_token",
        expire_at=now + timedelta(hours=1),
    )
    long_jwt = JWT(
        token="long_jwt_token",
        expire_at=now + timedelta(days=30),
    )
    return short_jwt, long_jwt


class TestSabianaHvacConfigFlowAsyncStepUser:
    @pytest.mark.asyncio
    async def test_async_step_user_shows_form_when_no_input(self, flow):
        result = await flow.async_step_user()
        flow.async_show_form.assert_called_once()
        assert result["type"] == FlowResultType.FORM

    @pytest.mark.asyncio
    async def test_async_step_user_creates_entry_on_successful_auth(
        self, flow, mock_hass, sample_jwt_tokens
    ):
        short_jwt, long_jwt = sample_jwt_tokens
        user_input = {
            CONF_EMAIL: "test@example.com",
            CONF_PASSWORD: "password123",
        }
        mock_session = Mock()
        with patch(
            "custom_components.sabiana_hvac.config_flow.get_async_client",
            return_value=mock_session,
        ), patch(
            "custom_components.sabiana_hvac.config_flow.api.async_authenticate",
            return_value=(short_jwt, long_jwt),
        ):
            result = await flow.async_step_user(user_input)
            flow.async_set_unique_id.assert_called_once_with("test@example.com")
            flow._abort_if_unique_id_configured.assert_called_once()
            flow.async_create_entry.assert_called_once()
            call_args = flow.async_create_entry.call_args
            assert call_args[1]["title"] == "Sabiana HVAC (test@example.com)"
            assert call_args[1]["data"][CONF_EMAIL] == "test@example.com"
            assert call_args[1]["data"][CONF_PASSWORD] == "password123"
            assert call_args[1]["data"][CONF_SHORT_JWT] == "short_jwt_token"
            assert call_args[1]["data"][CONF_LONG_JWT] == "long_jwt_token"
            assert result["type"] == FlowResultType.CREATE_ENTRY

    @pytest.mark.asyncio
    async def test_async_step_user_shows_error_on_auth_error(
        self, flow, mock_hass
    ):
        user_input = {
            CONF_EMAIL: "test@example.com",
            CONF_PASSWORD: "wrong_password",
        }
        mock_session = Mock()
        with patch(
            "custom_components.sabiana_hvac.config_flow.get_async_client",
            return_value=mock_session,
        ), patch(
            "custom_components.sabiana_hvac.config_flow.api.async_authenticate",
            side_effect=api.SabianaApiAuthError("Invalid credentials"),
        ):
            result = await flow.async_step_user(user_input)
            flow.async_show_form.assert_called_once()
            call_args = flow.async_show_form.call_args
            assert call_args[1]["errors"]["base"] == ERROR_INVALID_AUTH
            assert result["type"] == FlowResultType.FORM

    @pytest.mark.asyncio
    async def test_async_step_user_shows_error_on_connect_error(
        self, flow, mock_hass
    ):
        user_input = {
            CONF_EMAIL: "test@example.com",
            CONF_PASSWORD: "password123",
        }
        mock_session = Mock()
        with patch(
            "custom_components.sabiana_hvac.config_flow.get_async_client",
            return_value=mock_session,
        ), patch(
            "custom_components.sabiana_hvac.config_flow.api.async_authenticate",
            side_effect=httpx.ConnectError("Connection failed"),
        ):
            result = await flow.async_step_user(user_input)
            flow.async_show_form.assert_called_once()
            call_args = flow.async_show_form.call_args
            assert call_args[1]["errors"]["base"] == ERROR_CANNOT_CONNECT
            assert result["type"] == FlowResultType.FORM

    @pytest.mark.asyncio
    async def test_async_step_user_shows_error_on_timeout_error(
        self, flow, mock_hass
    ):
        user_input = {
            CONF_EMAIL: "test@example.com",
            CONF_PASSWORD: "password123",
        }
        mock_session = Mock()
        with patch(
            "custom_components.sabiana_hvac.config_flow.get_async_client",
            return_value=mock_session,
        ), patch(
            "custom_components.sabiana_hvac.config_flow.api.async_authenticate",
            side_effect=httpx.TimeoutException("Request timeout"),
        ):
            result = await flow.async_step_user(user_input)
            flow.async_show_form.assert_called_once()
            call_args = flow.async_show_form.call_args
            assert call_args[1]["errors"]["base"] == ERROR_TIMEOUT
            assert result["type"] == FlowResultType.FORM

    @pytest.mark.asyncio
    async def test_async_step_user_shows_error_on_api_client_error(
        self, flow, mock_hass
    ):
        user_input = {
            CONF_EMAIL: "test@example.com",
            CONF_PASSWORD: "password123",
        }
        mock_session = Mock()
        with patch(
            "custom_components.sabiana_hvac.config_flow.get_async_client",
            return_value=mock_session,
        ), patch(
            "custom_components.sabiana_hvac.config_flow.api.async_authenticate",
            side_effect=api.SabianaApiClientError("API error"),
        ):
            result = await flow.async_step_user(user_input)
            flow.async_show_form.assert_called_once()
            call_args = flow.async_show_form.call_args
            assert call_args[1]["errors"]["base"] == ERROR_API_ERROR
            assert result["type"] == FlowResultType.FORM

    @pytest.mark.asyncio
    async def test_async_step_user_shows_error_on_unexpected_error(
        self, flow, mock_hass
    ):
        user_input = {
            CONF_EMAIL: "test@example.com",
            CONF_PASSWORD: "password123",
        }
        mock_session = Mock()
        with patch(
            "custom_components.sabiana_hvac.config_flow.get_async_client",
            return_value=mock_session,
        ), patch(
            "custom_components.sabiana_hvac.config_flow.api.async_authenticate",
            side_effect=ValueError("Unexpected error"),
        ):
            result = await flow.async_step_user(user_input)
            flow.async_show_form.assert_called_once()
            call_args = flow.async_show_form.call_args
            assert call_args[1]["errors"]["base"] == ERROR_UNKNOWN
            assert result["type"] == FlowResultType.FORM

    @pytest.mark.asyncio
    async def test_async_step_user_lowercases_email_for_unique_id(
        self, flow, mock_hass, sample_jwt_tokens
    ):
        short_jwt, long_jwt = sample_jwt_tokens
        user_input = {
            CONF_EMAIL: "Test@Example.COM",
            CONF_PASSWORD: "password123",
        }
        mock_session = Mock()
        with patch(
            "custom_components.sabiana_hvac.config_flow.get_async_client",
            return_value=mock_session,
        ), patch(
            "custom_components.sabiana_hvac.config_flow.api.async_authenticate",
            return_value=(short_jwt, long_jwt),
        ):
            await flow.async_step_user(user_input)
            flow.async_set_unique_id.assert_called_once_with("test@example.com")

    @pytest.mark.asyncio
    async def test_async_step_user_stores_jwt_timestamps_correctly(
        self, flow, mock_hass, sample_jwt_tokens
    ):
        short_jwt, long_jwt = sample_jwt_tokens
        user_input = {
            CONF_EMAIL: "test@example.com",
            CONF_PASSWORD: "password123",
        }
        mock_session = Mock()
        with patch(
            "custom_components.sabiana_hvac.config_flow.get_async_client",
            return_value=mock_session,
        ), patch(
            "custom_components.sabiana_hvac.config_flow.api.async_authenticate",
            return_value=(short_jwt, long_jwt),
        ):
            await flow.async_step_user(user_input)
            call_args = flow.async_create_entry.call_args
            assert call_args[1]["data"][CONF_SHORT_JWT_EXPIRE_AT] == int(
                short_jwt.expire_at.timestamp()
            )
            assert call_args[1]["data"][CONF_LONG_JWT_EXPIRE_AT] == int(
                long_jwt.expire_at.timestamp()
            )

    @pytest.mark.asyncio
    async def test_async_step_user_shows_form_with_schema(
        self, flow
    ):
        result = await flow.async_step_user()
        call_args = flow.async_show_form.call_args
        assert call_args[1]["step_id"] == "user"
        schema = call_args[1]["data_schema"]
        assert schema is not None

