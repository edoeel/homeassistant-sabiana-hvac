"""Tests for the Sabiana HVAC API client."""

import base64
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from unittest.mock import Mock, patch

import httpx
import pytest
from pytest_httpx import HTTPXMock

from custom_components.sabiana_hvac import api
from custom_components.sabiana_hvac.api import (
    SabianaApiAuthError,
    SabianaApiClientError,
    SabianaDevice,
    _decode_swing_mode,
    decode_last_data,
)
from custom_components.sabiana_hvac.const import BASE_URL, USER_AGENT
from custom_components.sabiana_hvac.models import JWT

EXPECTED_DEVICE_COUNT = 2

# Expected temperature values for decode_last_data assertions
TEMP_22_5 = 22.5
TEMP_30_0 = 30.0
TEMP_35_0 = 35.0
TEMP_18_0 = 18.0
TEMP_20_0 = 20.0
TEMP_21_5 = 21.5
TEMP_24_0 = 24.0
TEMP_26_0 = 26.0


class TestSabianaApiClientError:
    """Tests for SabianaApiClientError exception."""

    def test_sabiana_api_client_error_can_be_raised(self) -> None:
        """Test that SabianaApiClientError can be raised."""
        error_message = "Test error"
        with pytest.raises(SabianaApiClientError, match=error_message):
            raise SabianaApiClientError(error_message)

    def test_sabiana_api_client_error_is_exception(self) -> None:
        """Test that SabianaApiClientError is an Exception."""
        error_message = "Test error"
        error = SabianaApiClientError(error_message)
        assert isinstance(error, Exception)


class TestSabianaApiAuthError:
    """Tests for SabianaApiAuthError exception."""

    def test_sabiana_api_auth_error_can_be_raised(self) -> None:
        """Test that SabianaApiAuthError can be raised."""
        error_message = "Auth error"
        with pytest.raises(SabianaApiAuthError, match=error_message):
            raise SabianaApiAuthError(error_message)

    def test_sabiana_api_auth_error_is_sabiana_api_client_error(self) -> None:
        """Test that SabianaApiAuthError is a SabianaApiClientError."""
        error_message = "Auth error"
        error = SabianaApiAuthError(error_message)
        assert isinstance(error, SabianaApiClientError)
        assert isinstance(error, Exception)


class TestSabianaDevice:
    """Tests for SabianaDevice dataclass."""

    def test_sabiana_device_can_be_created(self) -> None:
        """Test that SabianaDevice can be created with id and name."""
        device = SabianaDevice(id="device1", name="Device 1")
        assert device.id == "device1"
        assert device.name == "Device 1"

    def test_sabiana_device_is_frozen(self) -> None:
        """Test that SabianaDevice is frozen and cannot be modified."""
        device = SabianaDevice(id="device1", name="Device 1")
        with pytest.raises((AttributeError, TypeError)):
            device.id = "device2"


class TestCreateHeaders:
    """Tests for create_headers function."""

    def test_create_headers_returns_base_headers(self) -> None:
        """Test that create_headers returns base headers without auth."""
        headers = api.create_headers()
        assert headers["Host"] == "be-standard.sabianawm.cloud"
        assert headers["content-type"] == "application/json"
        assert headers["accept"] == "application/json, text/plain, */*"
        assert headers["user-agent"] == USER_AGENT
        assert "auth" not in headers

    def test_create_headers_includes_jwt_when_provided(self) -> None:
        """Test that create_headers includes auth header when JWT is provided."""
        jwt_value = "test_jwt_token"
        headers = api.create_headers(jwt_value)
        assert headers["auth"] == jwt_value

    def test_create_headers_renew_removes_auth_and_adds_renewauth(self) -> None:
        """Test that create_headers_renew uses renewauth instead of auth."""
        test_long_jwt = "long_jwt_token"
        headers = api.create_headers_renew(test_long_jwt)
        assert "auth" not in headers
        assert headers["renewauth"] == test_long_jwt
        assert headers["Host"] == "be-standard.sabianawm.cloud"


class TestIsHttpError:
    """Tests for is_http_error function."""

    def test_is_http_error_returns_false_for_success_codes(self) -> None:
        """Test that is_http_error returns False for success status codes."""
        assert api.is_http_error(200) is False
        assert api.is_http_error(201) is False
        assert api.is_http_error(299) is False

    def test_is_http_error_returns_true_for_error_codes(self) -> None:
        """Test that is_http_error returns True for error status codes."""
        assert api.is_http_error(400) is True
        assert api.is_http_error(401) is True
        assert api.is_http_error(500) is True


class TestIsAuthError:
    """Tests for is_auth_error function."""

    def test_is_auth_error_returns_true_for_401(self) -> None:
        """Test that is_auth_error returns True for 401 status code."""
        assert api.is_auth_error(401) is True

    def test_is_auth_error_returns_false_for_other_codes(self) -> None:
        """Test that is_auth_error returns False for other status codes."""
        assert api.is_auth_error(400) is False
        assert api.is_auth_error(403) is False
        assert api.is_auth_error(500) is False


class TestIsApiError:
    """Tests for is_api_error function."""

    def test_is_api_error_returns_false_for_status_zero(self) -> None:
        """Test that is_api_error returns False for status 0."""
        assert api.is_api_error({"status": 0}) is False

    def test_is_api_error_returns_true_for_non_zero_status(self) -> None:
        """Test that is_api_error returns True for non-zero status."""
        assert api.is_api_error({"status": 1}) is True
        assert api.is_api_error({"status": 99}) is True
        assert api.is_api_error({"status": 103}) is True

    def test_is_api_error_returns_false_when_status_missing(self) -> None:
        """Test that is_api_error returns False when status is missing."""
        assert api.is_api_error({}) is False


class TestIsAuthApiError:
    """Tests for is_auth_api_error function."""

    def test_is_auth_api_error_returns_true_for_status_99(self) -> None:
        """Test that is_auth_api_error returns True for status 99."""
        assert api.is_auth_api_error({"status": 99}) is True

    def test_is_auth_api_error_returns_true_for_status_103(self) -> None:
        """Test that is_auth_api_error returns True for status 103."""
        assert api.is_auth_api_error({"status": 103}) is True

    def test_is_auth_api_error_returns_false_for_other_status(self) -> None:
        """Test that is_auth_api_error returns False for other status codes."""
        assert api.is_auth_api_error({"status": 0}) is False
        assert api.is_auth_api_error({"status": 1}) is False
        assert api.is_auth_api_error({"status": 401}) is False


class TestValidateResponse:
    """Tests for validate_response function."""

    def test_validate_response_returns_data_for_valid_response(self) -> None:
        """Test that validate_response returns data for valid response."""
        response = Mock(spec=httpx.Response)
        response.status_code = 200
        response.json.return_value = {"status": 0, "body": {"data": "test"}}
        result = api.validate_response(response)
        assert result == {"status": 0, "body": {"data": "test"}}

    def test_validate_response_raises_auth_error_on_http_401(self) -> None:
        """Test that validate_response raises auth error on HTTP 401."""
        response = Mock(spec=httpx.Response)
        response.status_code = 401
        error_message = "Authentication error"
        with pytest.raises(SabianaApiAuthError, match=error_message):
            api.validate_response(response)

    def test_validate_response_raises_client_error_on_http_400(self) -> None:
        """Test that validate_response raises client error on HTTP 400."""
        response = Mock(spec=httpx.Response)
        response.status_code = 400
        error_message = "Request failed: 400"
        with pytest.raises(SabianaApiClientError, match=error_message):
            api.validate_response(response)

    def test_validate_response_raises_client_error_on_http_500(self) -> None:
        """Test that validate_response raises client error on HTTP 500."""
        response = Mock(spec=httpx.Response)
        response.status_code = 500
        error_message = "Request failed: 500"
        with pytest.raises(SabianaApiClientError, match=error_message):
            api.validate_response(response)

    def test_validate_response_raises_auth_error_on_api_status_99(self) -> None:
        """Test that validate_response raises auth error on API status 99."""
        response = Mock(spec=httpx.Response)
        response.status_code = 200
        error_message = "Auth failed"
        response.json.return_value = {
            "status": 99,
            "errorMessage": error_message,
        }
        with pytest.raises(SabianaApiAuthError, match=error_message):
            api.validate_response(response)

    def test_validate_response_raises_auth_error_on_api_status_103(self) -> None:
        """Test that validate_response raises auth error on API status 103."""
        response = Mock(spec=httpx.Response)
        response.status_code = 200
        error_message = "Token expired"
        response.json.return_value = {
            "status": 103,
            "errorMessage": error_message,
        }
        with pytest.raises(SabianaApiAuthError, match=error_message):
            api.validate_response(response)

    def test_validate_response_raises_client_error_on_api_error(self) -> None:
        """Test that validate_response raises client error on API error."""
        response = Mock(spec=httpx.Response)
        response.status_code = 200
        error_message = "API error"
        response.json.return_value = {
            "status": 1,
            "errorMessage": error_message,
        }
        with pytest.raises(SabianaApiClientError, match=error_message):
            api.validate_response(response)

    def test_validate_response_raises_client_error_with_default_message(self) -> None:
        """Test that validate_response raises client error with default message."""
        response = Mock(spec=httpx.Response)
        response.status_code = 200
        response.json.return_value = {"status": 1}
        error_message = "Unknown API error"
        with pytest.raises(SabianaApiClientError, match=error_message):
            api.validate_response(response)


class TestExtractJwtExpiry:
    """Tests for _extract_jwt_expiry function."""

    def test_extract_jwt_expiry_extracts_valid_exp_timestamp(self) -> None:
        """Test that _extract_jwt_expiry extracts valid exp timestamp."""
        exp_timestamp = int(datetime.now(UTC).timestamp()) + 3600
        token = self._create_jwt_with_exp(exp_timestamp)
        # Accessing private member for testing purposes
        result = api._extract_jwt_expiry(token)
        assert isinstance(result, datetime)
        assert result.timestamp() == exp_timestamp

    def test_extract_jwt_expiry_raises_error_for_invalid_format(self) -> None:
        """Test that _extract_jwt_expiry raises error for invalid format."""
        # Accessing private member for testing purposes
        with pytest.raises(SabianaApiClientError):
            api._extract_jwt_expiry("invalid.jwt")

    def test_extract_jwt_expiry_raises_error_for_missing_exp(self) -> None:
        """Test that _extract_jwt_expiry raises error for missing exp claim."""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "test_user"}
        token = self._create_jwt(header, payload)
        error_message = "missing 'exp' claim"
        # Accessing private member for testing purposes
        with pytest.raises(SabianaApiClientError, match=error_message):
            api._extract_jwt_expiry(token)

    def test_extract_jwt_expiry_handles_base64_padding(self) -> None:
        """Test that _extract_jwt_expiry handles base64 padding correctly."""
        exp_timestamp = int(datetime.now(UTC).timestamp()) + 3600
        header = {"alg": "HS256"}
        payload = {"exp": exp_timestamp}
        header_encoded = (
            base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        )
        payload_encoded = (
            base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        )
        token = f"{header_encoded}.{payload_encoded}.signature"
        # Accessing private member for testing purposes
        result = api._extract_jwt_expiry(token)
        assert result.timestamp() == exp_timestamp

    def _create_jwt_with_exp(self, exp_timestamp: int) -> str:
        """Create a JWT token with expiration timestamp."""
        return self._create_jwt(
            {"alg": "HS256", "typ": "JWT"},
            {"exp": exp_timestamp, "sub": "test"},
        )

    def _create_jwt(self, header: dict[str, Any], payload: dict[str, Any]) -> str:
        """Create a JWT token from header and payload."""
        header_encoded = (
            base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        )
        payload_encoded = (
            base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        )
        return f"{header_encoded}.{payload_encoded}.signature"


class TestCreateJwt:
    """Tests for _create_jwt function."""

    def test_create_jwt_creates_jwt_object_with_expiry(self) -> None:
        """Test that _create_jwt creates JWT object with expiry."""
        exp_timestamp = int(datetime.now(UTC).timestamp()) + 3600
        token = self._create_jwt_with_exp(exp_timestamp)
        # Accessing private member for testing purposes
        result = api._create_jwt(token)
        assert isinstance(result, JWT)
        assert result.token == token
        assert result.expire_at.timestamp() == exp_timestamp

    def _create_jwt_with_exp(self, exp_timestamp: int) -> str:
        """Create a JWT token with expiration timestamp."""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"exp": exp_timestamp, "sub": "test"}
        header_encoded = (
            base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        )
        payload_encoded = (
            base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        )
        return f"{header_encoded}.{payload_encoded}.signature"


class TestExtractJwts:
    """Tests for extract_jwts function."""

    def test_extract_jwts_returns_short_and_long_jwt_objects(
        self,
        sample_short_jwt_token: str,
        sample_long_jwt_token: str,
    ) -> None:
        """Test that extract_jwts returns short and long JWT objects."""
        data = {
            "body": {
                "user": {
                    "shortJwt": sample_short_jwt_token,
                    "longJwt": sample_long_jwt_token,
                },
            },
        }
        short_jwt, long_jwt = api.extract_jwts(data)
        assert isinstance(short_jwt, JWT)
        assert isinstance(long_jwt, JWT)
        assert short_jwt.token == sample_short_jwt_token
        assert long_jwt.token == sample_long_jwt_token


class TestExtractRenewedToken:
    """Tests for extract_renewed_token function."""

    def test_extract_renewed_token_returns_jwt_object(
        self,
        sample_short_jwt_token: str,
    ) -> None:
        """Test that extract_renewed_token returns JWT object."""
        data = {"body": {"newToken": sample_short_jwt_token}}
        result = api.extract_renewed_token(data)
        assert isinstance(result, JWT)
        assert result.token == sample_short_jwt_token


class TestExtractDevices:
    """Tests for extract_devices function."""

    def test_extract_devices_returns_list_of_devices(self) -> None:
        """Test that extract_devices returns list of devices."""
        data = {
            "body": {
                "devices": [
                    {"idDevice": "device1", "deviceName": "Device 1"},
                    {"idDevice": "device2", "deviceName": "Device 2"},
                ],
            },
        }
        devices = api.extract_devices(data)
        assert len(devices) == EXPECTED_DEVICE_COUNT
        assert isinstance(devices[0], SabianaDevice)
        assert devices[0].id == "device1"
        assert devices[0].name == "Device 1"
        assert devices[1].id == "device2"
        assert devices[1].name == "Device 2"

    def test_extract_devices_returns_empty_list_when_no_devices(self) -> None:
        """Test that extract_devices returns empty list when no devices."""
        data = {"body": {"devices": []}}
        devices = api.extract_devices(data)
        assert devices == []

    def test_extract_devices_returns_empty_list_when_body_missing(self) -> None:
        """Test that extract_devices returns empty list when body is missing."""
        data: dict[str, Any] = {}
        devices = api.extract_devices(data)
        assert devices == []

    def test_extract_devices_returns_empty_list_when_devices_missing(self) -> None:
        """Test that extract_devices returns empty list when devices is missing."""
        data = {"body": {}}
        devices = api.extract_devices(data)
        assert devices == []

    def test_extract_devices_uses_id_when_device_name_missing(self) -> None:
        """Test extract_devices falls back to idDevice when deviceName is absent."""
        data = {
            "body": {
                "devices": [
                    {"idDevice": "device1", "deviceName": "Device 1"},
                    {"idDevice": "device2"},
                ],
            },
        }
        devices = api.extract_devices(data)
        assert devices[1].id == "device2"
        assert devices[1].name == "device2"


class TestExtractResult:
    """Tests for extract_result function."""

    def test_extract_result_returns_true_when_result_is_true(self) -> None:
        """Test that extract_result returns True when result is True."""
        data = {"body": {"result": True}}
        assert api.extract_result(data) is True

    def test_extract_result_returns_false_when_result_is_false(self) -> None:
        """Test that extract_result returns False when result is False."""
        data = {"body": {"result": False}}
        assert api.extract_result(data) is False

    def test_extract_result_returns_false_when_result_missing(self) -> None:
        """Test that extract_result returns False when result is missing."""
        data = {"body": {}}
        assert api.extract_result(data) is False

    def test_extract_result_returns_false_when_body_missing(self) -> None:
        """Test that extract_result returns False when body is missing."""
        data: dict[str, Any] = {}
        assert api.extract_result(data) is False


class TestCreateSessionClient:
    """Tests for create_session_client function."""

    @patch("custom_components.sabiana_hvac.api.create_async_httpx_client")
    @patch("custom_components.sabiana_hvac.api.RetryTransport")
    def test_create_session_client_creates_client_with_retry_transport(
        self,
        mock_retry_transport: Mock,
        mock_create_client: Mock,
    ) -> None:
        """Test that create_session_client creates client with retry transport."""
        mock_hass = Mock()
        mock_client = Mock()
        mock_create_client.return_value = mock_client
        result = api.create_session_client(mock_hass)
        mock_create_client.assert_called_once_with(mock_hass, timeout=5.0)
        mock_retry_transport.assert_called_once()
        assert result == mock_client


class TestAsyncAuthenticate:
    """Tests for async_authenticate function."""

    @pytest.mark.asyncio
    async def test_async_authenticate_returns_jwt_tokens_on_success(
        self,
        httpx_mock: HTTPXMock,
        sample_authenticate_response: dict[str, Any],
    ) -> None:
        """Test that async_authenticate returns JWT tokens on success."""
        httpx_mock.add_response(
            url=f"{BASE_URL}/users/newLogin",
            method="POST",
            json=sample_authenticate_response,
        )
        async with httpx.AsyncClient() as session:
            short_jwt, long_jwt = await api.async_authenticate(
                session,
                "test@example.com",
                "password123",
            )
            assert isinstance(short_jwt, JWT)
            assert isinstance(long_jwt, JWT)

    @pytest.mark.asyncio
    async def test_async_authenticate_raises_auth_error_on_http_401(
        self,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Test that async_authenticate raises auth error on HTTP 401."""
        httpx_mock.add_response(
            url=f"{BASE_URL}/users/newLogin",
            method="POST",
            status_code=401,
        )
        async with httpx.AsyncClient() as session:
            with pytest.raises(SabianaApiAuthError):
                await api.async_authenticate(session, "test@example.com", "password123")

    @pytest.mark.asyncio
    async def test_async_authenticate_raises_auth_error_on_api_status_99(
        self,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Test that async_authenticate raises auth error on API status 99."""
        error_message = "Invalid credentials"
        httpx_mock.add_response(
            url=f"{BASE_URL}/users/newLogin",
            method="POST",
            json={"status": 99, "errorMessage": error_message},
        )
        async with httpx.AsyncClient() as session:
            with pytest.raises(SabianaApiAuthError, match=error_message):
                await api.async_authenticate(session, "test@example.com", "password123")

    @pytest.mark.asyncio
    async def test_async_authenticate_raises_client_error_on_api_error(
        self,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Test that async_authenticate raises client error on API error."""
        error_message = "Server error"
        httpx_mock.add_response(
            url=f"{BASE_URL}/users/newLogin",
            method="POST",
            json={"status": 1, "errorMessage": error_message},
        )
        async with httpx.AsyncClient() as session:
            with pytest.raises(SabianaApiClientError, match=error_message):
                await api.async_authenticate(session, "test@example.com", "password123")


class TestAsyncGetDevices:
    """Tests for async_get_devices function."""

    @pytest.mark.asyncio
    async def test_async_get_devices_returns_list_of_devices(
        self,
        httpx_mock: HTTPXMock,
        sample_devices_response: dict[str, Any],
        sample_short_jwt_token: str,
    ) -> None:
        """Test that async_get_devices returns list of devices."""
        httpx_mock.add_response(
            url=f"{BASE_URL}/devices/getDeviceForUserV2",
            method="GET",
            json=sample_devices_response,
        )
        async with httpx.AsyncClient() as session:
            devices = await api.async_get_devices(session, sample_short_jwt_token)
            assert len(devices) == EXPECTED_DEVICE_COUNT
            assert isinstance(devices[0], SabianaDevice)
            assert devices[0].id == "device1"
            assert devices[0].name == "Device 1"

    @pytest.mark.asyncio
    async def test_async_get_devices_raises_auth_error_on_http_401(
        self,
        httpx_mock: HTTPXMock,
        sample_short_jwt_token: str,
    ) -> None:
        """Test that async_get_devices raises auth error on HTTP 401."""
        httpx_mock.add_response(
            url=f"{BASE_URL}/devices/getDeviceForUserV2",
            method="GET",
            status_code=401,
        )
        async with httpx.AsyncClient() as session:
            with pytest.raises(SabianaApiAuthError):
                await api.async_get_devices(session, sample_short_jwt_token)

    @pytest.mark.asyncio
    async def test_async_get_devices_raises_auth_error_on_api_status_103(
        self,
        httpx_mock: HTTPXMock,
        sample_short_jwt_token: str,
    ) -> None:
        """Test that async_get_devices raises auth error on API status 103."""
        error_message = "Token expired"
        httpx_mock.add_response(
            url=f"{BASE_URL}/devices/getDeviceForUserV2",
            method="GET",
            json={"status": 103, "errorMessage": error_message},
        )
        async with httpx.AsyncClient() as session:
            with pytest.raises(SabianaApiAuthError, match=error_message):
                await api.async_get_devices(session, sample_short_jwt_token)


class TestAsyncRenewJwt:
    """Tests for async_renew_jwt function."""

    @pytest.mark.asyncio
    async def test_async_renew_jwt_returns_new_jwt_token(
        self,
        httpx_mock: HTTPXMock,
        sample_renew_jwt_response: dict[str, Any],
        sample_long_jwt_token: str,
    ) -> None:
        """Test that async_renew_jwt returns new JWT token."""
        httpx_mock.add_response(
            url=f"{BASE_URL}/renewJwt",
            method="POST",
            json=sample_renew_jwt_response,
        )
        async with httpx.AsyncClient() as session:
            new_jwt = await api.async_renew_jwt(session, sample_long_jwt_token)
            assert isinstance(new_jwt, JWT)

    @pytest.mark.asyncio
    async def test_async_renew_jwt_raises_auth_error_on_http_401(
        self,
        httpx_mock: HTTPXMock,
        sample_long_jwt_token: str,
    ) -> None:
        """Test that async_renew_jwt raises auth error on HTTP 401."""
        httpx_mock.add_response(
            url=f"{BASE_URL}/renewJwt",
            method="POST",
            status_code=401,
        )
        async with httpx.AsyncClient() as session:
            with pytest.raises(SabianaApiAuthError):
                await api.async_renew_jwt(session, sample_long_jwt_token)

    @pytest.mark.asyncio
    async def test_async_renew_jwt_raises_auth_error_on_api_status_99(
        self,
        httpx_mock: HTTPXMock,
        sample_long_jwt_token: str,
    ) -> None:
        """Test that async_renew_jwt raises auth error on API status 99."""
        error_message = "Invalid token"
        httpx_mock.add_response(
            url=f"{BASE_URL}/renewJwt",
            method="POST",
            json={"status": 99, "errorMessage": error_message},
        )
        async with httpx.AsyncClient() as session:
            with pytest.raises(SabianaApiAuthError, match=error_message):
                await api.async_renew_jwt(session, sample_long_jwt_token)


class TestAsyncSendCommand:
    """Tests for async_send_command function."""

    @pytest.mark.asyncio
    async def test_async_send_command_returns_true_on_success(
        self,
        httpx_mock: HTTPXMock,
        sample_send_command_response: dict[str, Any],
        sample_short_jwt_token: str,
    ) -> None:
        """Test that async_send_command returns True on success."""
        httpx_mock.add_response(
            url=f"{BASE_URL}/devices/cmd",
            method="POST",
            json=sample_send_command_response,
        )
        async with httpx.AsyncClient() as session:
            result = await api.async_send_command(
                session,
                sample_short_jwt_token,
                "device1",
                "command_data",
            )
            assert result is True

    @pytest.mark.asyncio
    async def test_async_send_command_returns_false_on_failure(
        self,
        httpx_mock: HTTPXMock,
        sample_short_jwt_token: str,
    ) -> None:
        """Test that async_send_command returns False on failure."""
        httpx_mock.add_response(
            url=f"{BASE_URL}/devices/cmd",
            method="POST",
            json={"status": 0, "body": {"result": False}},
        )
        async with httpx.AsyncClient() as session:
            result = await api.async_send_command(
                session,
                sample_short_jwt_token,
                "device1",
                "command_data",
            )
            assert result is False

    @pytest.mark.asyncio
    async def test_async_send_command_raises_auth_error_on_http_401(
        self,
        httpx_mock: HTTPXMock,
        sample_short_jwt_token: str,
    ) -> None:
        """Test that async_send_command raises auth error on HTTP 401."""
        httpx_mock.add_response(
            url=f"{BASE_URL}/devices/cmd",
            method="POST",
            status_code=401,
        )
        async with httpx.AsyncClient() as session:
            with pytest.raises(SabianaApiAuthError):
                await api.async_send_command(
                    session,
                    sample_short_jwt_token,
                    "device1",
                    "command_data",
                )

    @pytest.mark.asyncio
    async def test_async_send_command_raises_auth_error_on_api_status_103(
        self,
        httpx_mock: HTTPXMock,
        sample_short_jwt_token: str,
    ) -> None:
        """Test that async_send_command raises auth error on API status 103."""
        error_message = "Token expired"
        httpx_mock.add_response(
            url=f"{BASE_URL}/devices/cmd",
            method="POST",
            json={"status": 103, "errorMessage": error_message},
        )
        async with httpx.AsyncClient() as session:
            with pytest.raises(SabianaApiAuthError, match=error_message):
                await api.async_send_command(
                    session,
                    sample_short_jwt_token,
                    "device1",
                    "command_data",
                )


# ---------------------------------------------------------------------------
# Helpers for decode_last_data tests
# ---------------------------------------------------------------------------


@dataclass
class _HexFields:
    """Fields for building a lastData hex string.

    Byte layout:
      Word 1 (0-1):   model
      Word 2 (2-3):   unknown1
      Word 3 (4-5):   fan + mode
      Word 4 (6-7):   unknown2 + power/sleep
      Word 5 (8-9):   flap_pos + flap_present
      Word 6 (10-11): current_temp_raw  (x10)
      Word 7 (12-13): summer_sp_raw     (x10)
      Word 8 (14-15): winter_sp_raw     (x10)
      Word 9 (16-17): auto_sp_raw       (x10)
    """

    model: str = "5004"
    unknown1: str = "0000"
    fan: int = 0x04
    mode: int = 0x01
    unknown2: int = 0x00
    power: int = 0x01
    flap_pos: int = 0
    flap_present: int = 0
    current_temp_raw: int = 225
    summer_sp_raw: int = 220
    winter_sp_raw: int = 220
    auto_sp_raw: int = 220


def _build_hex(**kwargs: str | int) -> str:
    """Build a lastData hex string from field values."""
    f = _HexFields(**kwargs)
    return (
        f.model
        + f.unknown1
        + f"{f.fan:02x}{f.mode:02x}"
        + f"{f.unknown2:02x}{f.power:02x}"
        + f"{f.flap_pos:02x}{f.flap_present:02x}"
        + f"{f.current_temp_raw:04x}"
        + f"{f.summer_sp_raw:04x}"
        + f"{f.winter_sp_raw:04x}"
        + f"{f.auto_sp_raw:04x}"
    )


# ---------------------------------------------------------------------------
# decode_last_data tests
# ---------------------------------------------------------------------------


class TestDecodeLastDataCurrentTemperature:
    """Tests for current temperature decoding (16-bit word 6, bytes 10-11)."""

    def test_current_temp_normal_range(self) -> None:
        """Current temperature within single-byte range (≤ 25.5°C)."""
        hex_data = _build_hex(current_temp_raw=225)  # 22.5°C
        state = decode_last_data(hex_data)
        assert state.current_temperature == TEMP_22_5

    def test_current_temp_above_255(self) -> None:
        """Current temperature > 25.5°C requires 16-bit decoding."""
        hex_data = _build_hex(current_temp_raw=300)  # 30.0°C
        state = decode_last_data(hex_data)
        assert state.current_temperature == TEMP_30_0

    def test_current_temp_high_value(self) -> None:
        """Current temperature at 35.0°C (350 raw)."""
        hex_data = _build_hex(current_temp_raw=350)  # 35.0°C
        state = decode_last_data(hex_data)
        assert state.current_temperature == TEMP_35_0

    def test_current_temp_zero_returns_none(self) -> None:
        """Zero current temperature returns None."""
        hex_data = _build_hex(current_temp_raw=0)
        state = decode_last_data(hex_data)
        assert state.current_temperature is None

    def test_current_temp_fractional(self) -> None:
        """Current temperature 28.3°C (283 raw)."""
        hex_data = _build_hex(current_temp_raw=283)  # 28.3°C
        state = decode_last_data(hex_data)
        assert state.current_temperature == pytest.approx(28.3, abs=0.01)


class TestDecodeLastDataTargetTemperature:
    """Tests for mode-aware target temperature decoding."""

    def test_cool_mode_reads_summer_setpoint(self) -> None:
        """Cool mode (0) reads summer setpoint from bytes 12-13."""
        hex_data = _build_hex(
            mode=0x00,  # Cool / Summer
            summer_sp_raw=240,  # 24.0°C
            winter_sp_raw=180,  # 18.0°C — should NOT be read
            auto_sp_raw=200,  # 20.0°C — should NOT be read
        )
        state = decode_last_data(hex_data)
        assert state.target_temperature == TEMP_24_0

    def test_heat_mode_reads_winter_setpoint(self) -> None:
        """Heat mode (1) reads winter setpoint from bytes 14-15."""
        hex_data = _build_hex(
            mode=0x01,  # Heat / Winter
            summer_sp_raw=240,  # 24.0°C — should NOT be read
            winter_sp_raw=180,  # 18.0°C
            auto_sp_raw=200,  # 20.0°C — should NOT be read
        )
        state = decode_last_data(hex_data)
        assert state.target_temperature == TEMP_18_0

    def test_auto_mode_reads_auto_setpoint(self) -> None:
        """Auto mode (2) reads auto setpoint from bytes 16-17."""
        hex_data = _build_hex(
            mode=0x02,  # Auto
            summer_sp_raw=240,  # 24.0°C — should NOT be read
            winter_sp_raw=180,  # 18.0°C — should NOT be read
            auto_sp_raw=215,  # 21.5°C
        )
        state = decode_last_data(hex_data)
        assert state.target_temperature == TEMP_21_5

    def test_fan_only_mode_falls_back_to_winter(self) -> None:
        """Fan only mode (3) falls back to winter setpoint."""
        hex_data = _build_hex(
            mode=0x03,  # Fan only
            summer_sp_raw=240,
            winter_sp_raw=180,
            auto_sp_raw=200,
        )
        state = decode_last_data(hex_data)
        assert state.target_temperature == TEMP_18_0

    def test_cool_and_heat_have_different_setpoints(self) -> None:
        """Verify cool and heat modes read independent setpoints."""
        cool_hex = _build_hex(mode=0x00, summer_sp_raw=260, winter_sp_raw=200)
        heat_hex = _build_hex(mode=0x01, summer_sp_raw=260, winter_sp_raw=200)

        cool_state = decode_last_data(cool_hex)
        heat_state = decode_last_data(heat_hex)

        assert cool_state.target_temperature == TEMP_26_0  # summer
        assert heat_state.target_temperature == TEMP_20_0  # winter


class TestDecodeLastDataSwingMode:
    """Tests for swing/flap mode decoding (word 5, bytes 8-9)."""

    def test_flap_present_position_horizontal(self) -> None:
        """Flap present with position 1 → 'Horizontal'."""
        hex_data = _build_hex(flap_pos=1, flap_present=1)
        state = decode_last_data(hex_data)
        assert state.swing_mode == "Horizontal"

    def test_flap_present_position_45_degrees(self) -> None:
        """Flap present with position 2 → '45 Degrees'."""
        hex_data = _build_hex(flap_pos=2, flap_present=1)
        state = decode_last_data(hex_data)
        assert state.swing_mode == "45 Degrees"

    def test_flap_present_position_vertical(self) -> None:
        """Flap present with position 3 → 'Vertical'."""
        hex_data = _build_hex(flap_pos=3, flap_present=1)
        state = decode_last_data(hex_data)
        assert state.swing_mode == "Vertical"

    def test_flap_present_position_swing(self) -> None:
        """Flap present with position 4 → 'Swing'."""
        hex_data = _build_hex(flap_pos=4, flap_present=1)
        state = decode_last_data(hex_data)
        assert state.swing_mode == "Swing"

    def test_flap_present_position_standard_returns_none(self) -> None:
        """Flap present with position 0 (Standard) → None (not in modes list)."""
        hex_data = _build_hex(flap_pos=0, flap_present=1)
        state = decode_last_data(hex_data)
        assert state.swing_mode is None

    def test_flap_not_present_returns_none(self) -> None:
        """Flap not present (flag=0) → None regardless of position."""
        hex_data = _build_hex(flap_pos=4, flap_present=0)
        state = decode_last_data(hex_data)
        assert state.swing_mode is None

    def test_flap_unknown_present_value_returns_none(self) -> None:
        """Flap present flag not 1 (e.g. 2) → None."""
        hex_data = _build_hex(flap_pos=4, flap_present=2)
        state = decode_last_data(hex_data)
        assert state.swing_mode is None


class TestDecodeSwingModeFunction:
    """Unit tests for _decode_swing_mode helper."""

    def test_all_positions(self) -> None:
        """Each valid position maps to correct swing mode name."""
        assert _decode_swing_mode(1, 1) == "Horizontal"
        assert _decode_swing_mode(2, 1) == "45 Degrees"
        assert _decode_swing_mode(3, 1) == "Vertical"
        assert _decode_swing_mode(4, 1) == "Swing"

    def test_position_zero_returns_none(self) -> None:
        """Position 0 (Standard) returns None."""
        assert _decode_swing_mode(0, 1) is None

    def test_not_present_returns_none(self) -> None:
        """Flap not present returns None."""
        assert _decode_swing_mode(4, 0) is None

    def test_unknown_position_returns_none(self) -> None:
        """Unknown position value returns None."""
        assert _decode_swing_mode(5, 1) is None
        assert _decode_swing_mode(255, 1) is None


class TestDecodeLastDataHvacMode:
    """Tests for HVAC mode decoding including the DRY→AUTO fix."""

    def test_mode_0_is_cool(self) -> None:
        """Mode byte 0 decodes to 'cool'."""
        hex_data = _build_hex(mode=0x00)
        state = decode_last_data(hex_data)
        assert state.hvac_mode == "cool"

    def test_mode_1_is_heat(self) -> None:
        """Mode byte 1 decodes to 'heat'."""
        hex_data = _build_hex(mode=0x01)
        state = decode_last_data(hex_data)
        assert state.hvac_mode == "heat"

    def test_mode_2_is_auto(self) -> None:
        """Mode byte 2 decodes to 'auto' (not 'dry')."""
        hex_data = _build_hex(mode=0x02)
        state = decode_last_data(hex_data)
        assert state.hvac_mode == "auto"

    def test_mode_3_is_fan_only(self) -> None:
        """Mode byte 3 decodes to 'fan_only'."""
        hex_data = _build_hex(mode=0x03)
        state = decode_last_data(hex_data)
        assert state.hvac_mode == "fan_only"

    def test_power_off_overrides_mode(self) -> None:
        """Power off (byte 7 bit 0 = 0) overrides mode to 'off'."""
        hex_data = _build_hex(mode=0x01, power=0x00)
        state = decode_last_data(hex_data)
        assert state.hvac_mode == "off"
        assert state.power_on is False

    def test_power_off_with_auto_available_overrides_mode(self) -> None:
        """Power off with auto available (byte 7 = 0x04) overrides mode to 'off'."""
        hex_data = _build_hex(mode=0x01, power=0x04)
        state = decode_last_data(hex_data)
        assert state.hvac_mode == "off"
        assert state.power_on is False


class TestDecodeLastDataAutoModeAvailable:
    """Tests for auto mode availability flag (bit 2 of byte 7)."""

    def test_auto_mode_not_available_default(self) -> None:
        """Default power=0x01 has bit 2 clear → auto mode not available."""
        hex_data = _build_hex(power=0x01)
        state = decode_last_data(hex_data)
        assert state.auto_mode_available is False

    def test_auto_mode_available_when_bit2_set(self) -> None:
        """Power byte 0x05 (bit 0 + bit 2) → power on + auto mode available."""
        hex_data = _build_hex(power=0x05)
        state = decode_last_data(hex_data)
        assert state.auto_mode_available is True
        assert state.power_on is True

    def test_auto_mode_available_with_only_bit2(self) -> None:
        """Power byte 0x04 (only bit 2) → auto mode flag is set, power is OFF."""
        hex_data = _build_hex(power=0x04)
        state = decode_last_data(hex_data)
        assert state.auto_mode_available is True
        assert state.power_on is False

    def test_auto_mode_not_available_with_sleep(self) -> None:
        """Power byte 0x81 (sleep + power on) → auto mode not available."""
        hex_data = _build_hex(power=0x81)
        state = decode_last_data(hex_data)
        assert state.auto_mode_available is False
        assert state.preset_mode == "sleep"

    def test_auto_mode_available_with_sleep(self) -> None:
        """Power byte 0x85 (sleep + power + auto) → both available."""
        hex_data = _build_hex(power=0x85)
        state = decode_last_data(hex_data)
        assert state.auto_mode_available is True
        assert state.preset_mode == "sleep"
        assert state.power_on is True

    def test_empty_state_has_auto_mode_false(self) -> None:
        """Empty/error states default to auto_mode_available=False."""
        state = decode_last_data("")
        assert state.auto_mode_available is False

        state = decode_last_data("ZZZZ")
        assert state.auto_mode_available is False

        state = decode_last_data("0000")
        assert state.auto_mode_available is False


class TestDecodeLastDataEdgeCases:
    """Edge case tests for decode_last_data."""

    def test_data_too_short_returns_empty_state(self) -> None:
        """Data shorter than 18 bytes returns empty state."""
        hex_data = "0000" * 8  # 16 bytes, need 18
        state = decode_last_data(hex_data)
        assert state.hvac_mode is None
        assert state.target_temperature is None

    def test_invalid_hex_returns_empty_state(self) -> None:
        """Invalid hex string returns empty state with error."""
        state = decode_last_data("ZZZZ")
        assert state.hvac_mode is None
        assert state.raw_state.get("error") == "decode_error"

    def test_empty_string_returns_empty_state(self) -> None:
        """Empty string returns empty state."""
        state = decode_last_data("")
        assert state.hvac_mode is None

    def test_full_decode_round_trip(self) -> None:
        """A complete decode with all fields set produces valid state."""
        hex_data = _build_hex(
            model="500B",
            fan=0x03,  # high
            mode=0x00,  # cool
            power=0x01,
            flap_pos=4,  # swing
            flap_present=1,
            current_temp_raw=283,  # 28.3°C
            summer_sp_raw=240,  # 24.0°C
            winter_sp_raw=200,  # 20.0°C
            auto_sp_raw=220,  # 22.0°C
        )
        state = decode_last_data(hex_data)

        assert state.hvac_mode == "cool"
        assert state.power_on is True
        assert state.current_temperature == pytest.approx(28.3, abs=0.01)
        assert state.target_temperature == TEMP_24_0  # cool → summer setpoint
        assert state.swing_mode == "Swing"
        assert state.fan_mode == "high"

    def test_preset_sleep_mode(self) -> None:
        """Preset mode decoded from byte 7 bit 7."""
        hex_data = _build_hex(power=0x81)  # bit 7 set = sleep, lower nibble = 1 = on
        state = decode_last_data(hex_data)
        assert state.preset_mode == "sleep"
        assert state.power_on is True

    def test_preset_none_mode(self) -> None:
        """Preset mode is 'none' when byte 7 bit 7 is unset."""
        hex_data = _build_hex(power=0x01)
        state = decode_last_data(hex_data)
        assert state.preset_mode == "none"
