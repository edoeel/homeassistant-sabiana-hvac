"""Tests for the Sabiana HVAC API client."""

import base64
import json
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
)
from custom_components.sabiana_hvac.const import BASE_URL, USER_AGENT
from custom_components.sabiana_hvac.models import JWT

EXPECTED_DEVICE_COUNT = 2


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
