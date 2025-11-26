import base64
import json
from datetime import UTC, datetime
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


class TestSabianaApiClientError:
    def test_sabiana_api_client_error_can_be_raised(self):
        with pytest.raises(SabianaApiClientError, match="Test error"):
            raise SabianaApiClientError("Test error")

    def test_sabiana_api_client_error_is_exception(self):
        error = SabianaApiClientError("Test error")
        assert isinstance(error, Exception)


class TestSabianaApiAuthError:
    def test_sabiana_api_auth_error_can_be_raised(self):
        with pytest.raises(SabianaApiAuthError, match="Auth error"):
            raise SabianaApiAuthError("Auth error")

    def test_sabiana_api_auth_error_is_sabiana_api_client_error(self):
        error = SabianaApiAuthError("Auth error")
        assert isinstance(error, SabianaApiClientError)
        assert isinstance(error, Exception)


class TestSabianaDevice:
    def test_sabiana_device_can_be_created(self):
        device = SabianaDevice(id="device1", name="Device 1")
        assert device.id == "device1"
        assert device.name == "Device 1"

    def test_sabiana_device_is_frozen(self):
        device = SabianaDevice(id="device1", name="Device 1")
        with pytest.raises((AttributeError, TypeError)):
            device.id = "device2"


class TestCreateHeaders:
    def test_create_headers_returns_base_headers(self):
        headers = api.create_headers()
        assert headers["Host"] == "be-standard.sabianawm.cloud"
        assert headers["content-type"] == "application/json"
        assert headers["accept"] == "application/json, text/plain, */*"
        assert headers["user-agent"] == USER_AGENT
        assert "auth" not in headers

    def test_create_headers_includes_jwt_when_provided(self):
        jwt_token = "test_jwt_token"
        headers = api.create_headers(jwt_token)
        assert headers["auth"] == jwt_token

    def test_create_headers_renew_removes_auth_and_adds_renewauth(self):
        long_jwt = "long_jwt_token"
        headers = api.create_headers_renew(long_jwt)
        assert "auth" not in headers
        assert headers["renewauth"] == long_jwt
        assert headers["Host"] == "be-standard.sabianawm.cloud"


class TestIsHttpError:
    def test_is_http_error_returns_false_for_success_codes(self):
        assert api.is_http_error(200) is False
        assert api.is_http_error(201) is False
        assert api.is_http_error(299) is False

    def test_is_http_error_returns_true_for_error_codes(self):
        assert api.is_http_error(400) is True
        assert api.is_http_error(401) is True
        assert api.is_http_error(500) is True


class TestIsAuthError:
    def test_is_auth_error_returns_true_for_401(self):
        assert api.is_auth_error(401) is True

    def test_is_auth_error_returns_false_for_other_codes(self):
        assert api.is_auth_error(400) is False
        assert api.is_auth_error(403) is False
        assert api.is_auth_error(500) is False


class TestIsApiError:
    def test_is_api_error_returns_false_for_status_zero(self):
        assert api.is_api_error({"status": 0}) is False

    def test_is_api_error_returns_true_for_non_zero_status(self):
        assert api.is_api_error({"status": 1}) is True
        assert api.is_api_error({"status": 99}) is True
        assert api.is_api_error({"status": 103}) is True

    def test_is_api_error_returns_false_when_status_missing(self):
        assert api.is_api_error({}) is False


class TestIsAuthApiError:
    def test_is_auth_api_error_returns_true_for_status_99(self):
        assert api.is_auth_api_error({"status": 99}) is True

    def test_is_auth_api_error_returns_true_for_status_103(self):
        assert api.is_auth_api_error({"status": 103}) is True

    def test_is_auth_api_error_returns_false_for_other_status(self):
        assert api.is_auth_api_error({"status": 0}) is False
        assert api.is_auth_api_error({"status": 1}) is False
        assert api.is_auth_api_error({"status": 401}) is False


class TestValidateResponse:
    def test_validate_response_returns_data_for_valid_response(self):
        response = Mock(spec=httpx.Response)
        response.status_code = 200
        response.json.return_value = {"status": 0, "body": {"data": "test"}}
        result = api.validate_response(response)
        assert result == {"status": 0, "body": {"data": "test"}}

    def test_validate_response_raises_auth_error_on_http_401(self):
        response = Mock(spec=httpx.Response)
        response.status_code = 401
        with pytest.raises(SabianaApiAuthError, match="Authentication error"):
            api.validate_response(response)

    def test_validate_response_raises_client_error_on_http_400(self):
        response = Mock(spec=httpx.Response)
        response.status_code = 400
        with pytest.raises(SabianaApiClientError, match="Request failed: 400"):
            api.validate_response(response)

    def test_validate_response_raises_client_error_on_http_500(self):
        response = Mock(spec=httpx.Response)
        response.status_code = 500
        with pytest.raises(SabianaApiClientError, match="Request failed: 500"):
            api.validate_response(response)

    def test_validate_response_raises_auth_error_on_api_status_99(self):
        response = Mock(spec=httpx.Response)
        response.status_code = 200
        response.json.return_value = {
            "status": 99,
            "errorMessage": "Auth failed",
        }
        with pytest.raises(SabianaApiAuthError, match="Auth failed"):
            api.validate_response(response)

    def test_validate_response_raises_auth_error_on_api_status_103(self):
        response = Mock(spec=httpx.Response)
        response.status_code = 200
        response.json.return_value = {
            "status": 103,
            "errorMessage": "Token expired",
        }
        with pytest.raises(SabianaApiAuthError, match="Token expired"):
            api.validate_response(response)

    def test_validate_response_raises_client_error_on_api_error(self):
        response = Mock(spec=httpx.Response)
        response.status_code = 200
        response.json.return_value = {
            "status": 1,
            "errorMessage": "API error",
        }
        with pytest.raises(SabianaApiClientError, match="API error"):
            api.validate_response(response)

    def test_validate_response_raises_client_error_with_default_message(self):
        response = Mock(spec=httpx.Response)
        response.status_code = 200
        response.json.return_value = {"status": 1}
        with pytest.raises(SabianaApiClientError, match="Unknown API error"):
            api.validate_response(response)


class TestExtractJwtExpiry:
    def test_extract_jwt_expiry_extracts_valid_exp_timestamp(self):
        exp_timestamp = int(datetime.now(UTC).timestamp()) + 3600
        token = self._create_jwt_with_exp(exp_timestamp)
        result = api._extract_jwt_expiry(token)
        assert isinstance(result, datetime)
        assert result.timestamp() == exp_timestamp

    def test_extract_jwt_expiry_raises_error_for_invalid_format(self):
        with pytest.raises(SabianaApiClientError):
            api._extract_jwt_expiry("invalid.jwt")

    def test_extract_jwt_expiry_raises_error_for_missing_exp(self):
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "test_user"}
        token = self._create_jwt(header, payload)
        with pytest.raises(SabianaApiClientError, match="missing 'exp' claim"):
            api._extract_jwt_expiry(token)

    def test_extract_jwt_expiry_handles_base64_padding(self):
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
        result = api._extract_jwt_expiry(token)
        assert result.timestamp() == exp_timestamp

    def _create_jwt_with_exp(self, exp_timestamp: int) -> str:
        return self._create_jwt(
            {"alg": "HS256", "typ": "JWT"}, {"exp": exp_timestamp, "sub": "test"}
        )

    def _create_jwt(self, header: dict, payload: dict) -> str:
        header_encoded = (
            base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        )
        payload_encoded = (
            base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        )
        return f"{header_encoded}.{payload_encoded}.signature"


class TestCreateJwt:
    def test_create_jwt_creates_jwt_object_with_expiry(self):
        exp_timestamp = int(datetime.now(UTC).timestamp()) + 3600
        token = self._create_jwt_with_exp(exp_timestamp)
        result = api._create_jwt(token)
        assert isinstance(result, JWT)
        assert result.token == token
        assert result.expire_at.timestamp() == exp_timestamp

    def _create_jwt_with_exp(self, exp_timestamp: int) -> str:
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
    def test_extract_jwts_returns_short_and_long_jwt_objects(
        self, sample_short_jwt_token, sample_long_jwt_token
    ):
        data = {
            "body": {
                "user": {
                    "shortJwt": sample_short_jwt_token,
                    "longJwt": sample_long_jwt_token,
                }
            }
        }
        short_jwt, long_jwt = api.extract_jwts(data)
        assert isinstance(short_jwt, JWT)
        assert isinstance(long_jwt, JWT)
        assert short_jwt.token == sample_short_jwt_token
        assert long_jwt.token == sample_long_jwt_token


class TestExtractRenewedToken:
    def test_extract_renewed_token_returns_jwt_object(self, sample_short_jwt_token):
        data = {"body": {"newToken": sample_short_jwt_token}}
        result = api.extract_renewed_token(data)
        assert isinstance(result, JWT)
        assert result.token == sample_short_jwt_token


class TestExtractDevices:
    def test_extract_devices_returns_list_of_devices(self):
        data = {
            "body": {
                "devices": [
                    {"idDevice": "device1", "deviceName": "Device 1"},
                    {"idDevice": "device2", "deviceName": "Device 2"},
                ]
            }
        }
        devices = api.extract_devices(data)
        assert len(devices) == 2
        assert isinstance(devices[0], SabianaDevice)
        assert devices[0].id == "device1"
        assert devices[0].name == "Device 1"
        assert devices[1].id == "device2"
        assert devices[1].name == "Device 2"

    def test_extract_devices_returns_empty_list_when_no_devices(self):
        data = {"body": {"devices": []}}
        devices = api.extract_devices(data)
        assert devices == []

    def test_extract_devices_returns_empty_list_when_body_missing(self):
        data = {}
        devices = api.extract_devices(data)
        assert devices == []

    def test_extract_devices_returns_empty_list_when_devices_missing(self):
        data = {"body": {}}
        devices = api.extract_devices(data)
        assert devices == []


class TestExtractResult:
    def test_extract_result_returns_true_when_result_is_true(self):
        data = {"body": {"result": True}}
        assert api.extract_result(data) is True

    def test_extract_result_returns_false_when_result_is_false(self):
        data = {"body": {"result": False}}
        assert api.extract_result(data) is False

    def test_extract_result_returns_false_when_result_missing(self):
        data = {"body": {}}
        assert api.extract_result(data) is False

    def test_extract_result_returns_false_when_body_missing(self):
        data = {}
        assert api.extract_result(data) is False


class TestCreateSessionClient:
    @patch("custom_components.sabiana_hvac.api.create_async_httpx_client")
    @patch("custom_components.sabiana_hvac.api.RetryTransport")
    def test_create_session_client_creates_client_with_retry_transport(
        self, mock_retry_transport, mock_create_client
    ):
        mock_hass = Mock()
        mock_client = Mock()
        mock_create_client.return_value = mock_client
        result = api.create_session_client(mock_hass)
        mock_create_client.assert_called_once_with(mock_hass, timeout=5.0)
        mock_retry_transport.assert_called_once()
        assert result == mock_client


class TestAsyncAuthenticate:
    @pytest.mark.asyncio
    async def test_async_authenticate_returns_jwt_tokens_on_success(
        self, httpx_mock: HTTPXMock, sample_authenticate_response
    ):
        httpx_mock.add_response(
            url=f"{BASE_URL}/users/newLogin",
            method="POST",
            json=sample_authenticate_response,
        )
        async with httpx.AsyncClient() as session:
            short_jwt, long_jwt = await api.async_authenticate(
                session, "test@example.com", "password123"
            )
            assert isinstance(short_jwt, JWT)
            assert isinstance(long_jwt, JWT)

    @pytest.mark.asyncio
    async def test_async_authenticate_raises_auth_error_on_http_401(
        self, httpx_mock: HTTPXMock
    ):
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
        self, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(
            url=f"{BASE_URL}/users/newLogin",
            method="POST",
            json={"status": 99, "errorMessage": "Invalid credentials"},
        )
        async with httpx.AsyncClient() as session:
            with pytest.raises(SabianaApiAuthError, match="Invalid credentials"):
                await api.async_authenticate(session, "test@example.com", "password123")

    @pytest.mark.asyncio
    async def test_async_authenticate_raises_client_error_on_api_error(
        self, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(
            url=f"{BASE_URL}/users/newLogin",
            method="POST",
            json={"status": 1, "errorMessage": "Server error"},
        )
        async with httpx.AsyncClient() as session:
            with pytest.raises(SabianaApiClientError, match="Server error"):
                await api.async_authenticate(session, "test@example.com", "password123")


class TestAsyncGetDevices:
    @pytest.mark.asyncio
    async def test_async_get_devices_returns_list_of_devices(
        self, httpx_mock: HTTPXMock, sample_devices_response, sample_short_jwt_token
    ):
        httpx_mock.add_response(
            url=f"{BASE_URL}/devices/getDeviceForUserV2",
            method="GET",
            json=sample_devices_response,
        )
        async with httpx.AsyncClient() as session:
            devices = await api.async_get_devices(session, sample_short_jwt_token)
            assert len(devices) == 2
            assert isinstance(devices[0], SabianaDevice)
            assert devices[0].id == "device1"
            assert devices[0].name == "Device 1"

    @pytest.mark.asyncio
    async def test_async_get_devices_raises_auth_error_on_http_401(
        self, httpx_mock: HTTPXMock, sample_short_jwt_token
    ):
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
        self, httpx_mock: HTTPXMock, sample_short_jwt_token
    ):
        httpx_mock.add_response(
            url=f"{BASE_URL}/devices/getDeviceForUserV2",
            method="GET",
            json={"status": 103, "errorMessage": "Token expired"},
        )
        async with httpx.AsyncClient() as session:
            with pytest.raises(SabianaApiAuthError, match="Token expired"):
                await api.async_get_devices(session, sample_short_jwt_token)


class TestAsyncRenewJwt:
    @pytest.mark.asyncio
    async def test_async_renew_jwt_returns_new_jwt_token(
        self, httpx_mock: HTTPXMock, sample_renew_jwt_response, sample_long_jwt_token
    ):
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
        self, httpx_mock: HTTPXMock, sample_long_jwt_token
    ):
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
        self, httpx_mock: HTTPXMock, sample_long_jwt_token
    ):
        httpx_mock.add_response(
            url=f"{BASE_URL}/renewJwt",
            method="POST",
            json={"status": 99, "errorMessage": "Invalid token"},
        )
        async with httpx.AsyncClient() as session:
            with pytest.raises(SabianaApiAuthError, match="Invalid token"):
                await api.async_renew_jwt(session, sample_long_jwt_token)


class TestAsyncSendCommand:
    @pytest.mark.asyncio
    async def test_async_send_command_returns_true_on_success(
        self,
        httpx_mock: HTTPXMock,
        sample_send_command_response,
        sample_short_jwt_token,
    ):
        httpx_mock.add_response(
            url=f"{BASE_URL}/devices/cmd",
            method="POST",
            json=sample_send_command_response,
        )
        async with httpx.AsyncClient() as session:
            result = await api.async_send_command(
                session, sample_short_jwt_token, "device1", "command_data"
            )
            assert result is True

    @pytest.mark.asyncio
    async def test_async_send_command_returns_false_on_failure(
        self, httpx_mock: HTTPXMock, sample_short_jwt_token
    ):
        httpx_mock.add_response(
            url=f"{BASE_URL}/devices/cmd",
            method="POST",
            json={"status": 0, "body": {"result": False}},
        )
        async with httpx.AsyncClient() as session:
            result = await api.async_send_command(
                session, sample_short_jwt_token, "device1", "command_data"
            )
            assert result is False

    @pytest.mark.asyncio
    async def test_async_send_command_raises_auth_error_on_http_401(
        self, httpx_mock: HTTPXMock, sample_short_jwt_token
    ):
        httpx_mock.add_response(
            url=f"{BASE_URL}/devices/cmd",
            method="POST",
            status_code=401,
        )
        async with httpx.AsyncClient() as session:
            with pytest.raises(SabianaApiAuthError):
                await api.async_send_command(
                    session, sample_short_jwt_token, "device1", "command_data"
                )

    @pytest.mark.asyncio
    async def test_async_send_command_raises_auth_error_on_api_status_103(
        self, httpx_mock: HTTPXMock, sample_short_jwt_token
    ):
        httpx_mock.add_response(
            url=f"{BASE_URL}/devices/cmd",
            method="POST",
            json={"status": 103, "errorMessage": "Token expired"},
        )
        async with httpx.AsyncClient() as session:
            with pytest.raises(SabianaApiAuthError, match="Token expired"):
                await api.async_send_command(
                    session, sample_short_jwt_token, "device1", "command_data"
                )
