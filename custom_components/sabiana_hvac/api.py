# Copyright (c) 2026 Edoardo Mistretta

"""API client for Sabiana HVAC systems.

This module provides functions to interact with the Sabiana API,
including authentication, device management, and command sending.
"""

import base64
import json
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from homeassistant.helpers.httpx_client import create_async_httpx_client
from httpx_retries import Retry, RetryTransport

from .const import BASE_URL, USER_AGENT
from .models import JWT, SabianaDevice, SabianaDeviceList
from .protocol import COMMAND_START, decode_device_data

if TYPE_CHECKING:
    import httpx
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

# HTTP status codes
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401


class SabianaApiClientError(Exception):
    """Base exception for Sabiana API client errors."""


class SabianaApiAuthError(SabianaApiClientError):
    """Exception raised for authentication errors."""


# Re-exported: SabianaDevice used to live here.
__all__ = ["SabianaDevice", "SabianaDeviceList"]

# A rotated long JWT is accepted only if longer than this (app: checkResponse).
_MIN_ROTATED_TOKEN_LENGTH = 10


def create_headers(short_jwt: str | None = None) -> dict[str, str]:
    """Create HTTP headers for Sabiana API requests.

    Args:
        short_jwt: Optional short-term JWT to include in headers.

    Returns:
        Dictionary containing HTTP headers for API requests.

    """
    headers = {
        "Host": "be-standard.sabianawm.cloud",
        "content-type": "application/json",
        "accept": "application/json, text/plain, */*",
        "sec-fetch-site": "cross-site",
        "accept-language": "it-IT,it;q=0.9",
        "sec-fetch-mode": "cors",
        "origin": "capacitor://sabianawm.cloud",
        "user-agent": USER_AGENT,
        "sec-fetch-dest": "empty",
    }
    if short_jwt:
        headers["auth"] = short_jwt
    return headers


def create_headers_renew(long_jwt: str) -> dict[str, str]:
    """Create HTTP headers for JWT renewal requests.

    Args:
        long_jwt: Long-term JWT to include in headers as "renewauth".

    Returns:
        Dictionary containing HTTP headers for renewal requests.

    """
    headers = create_headers()
    headers.pop("auth", None)
    headers["renewauth"] = long_jwt
    return headers


def is_http_error(status: int) -> bool:
    """Check if HTTP status code indicates an error.

    Args:
        status: HTTP status code to check.

    Returns:
        True if status code is 400 or higher, False otherwise.

    """
    return status >= HTTP_BAD_REQUEST


def is_auth_error(status: int) -> bool:
    """Check if HTTP status code indicates authentication error.

    Args:
        status: HTTP status code to check.

    Returns:
        True if status code is 401, False otherwise.

    """
    return status == HTTP_UNAUTHORIZED


def is_api_error(data: dict[str, Any]) -> bool:
    """Check if API response indicates an error.

    Args:
        data: API response data dictionary.

    Returns:
        True if status field is not 0, False otherwise.

    """
    return data.get("status", 0) != 0


def is_auth_api_error(data: dict[str, Any]) -> bool:
    """Check if API response indicates authentication error.

    Args:
        data: API response data dictionary.

    Returns:
        True if status field is 99 or 103, False otherwise.

    """
    return data.get("status", 0) in [99, 103]


def validate_response(response: httpx.Response) -> dict[str, Any]:
    """Validate HTTP response and return parsed JSON data.

    Args:
        response: HTTP response object to validate.

    Returns:
        Parsed JSON data from response.

    Raises:
        SabianaApiAuthError: If authentication error is detected.
        SabianaApiClientError: If API error is detected.

    """
    _validate_http_status(response)
    data = response.json()
    _validate_api_status(data)
    return data


def _validate_http_status(response: httpx.Response) -> None:
    if not is_http_error(response.status_code):
        return

    if is_auth_error(response.status_code):
        auth_error = "Authentication error"
        raise SabianaApiAuthError(auth_error)

    client_error = f"Request failed: {response.status_code}"
    raise SabianaApiClientError(client_error)


def _validate_api_status(data: dict[str, Any]) -> None:
    if not is_api_error(data):
        return

    error_message = data.get("errorMessage", "Unknown API error")

    if is_auth_api_error(data):
        raise SabianaApiAuthError(error_message)

    raise SabianaApiClientError(error_message)


def _extract_jwt_expiry(token: str) -> datetime:
    """Extract expiration timestamp from JWT token's 'exp' claim.

    Args:
        token: JWT token string.

    Returns:
        Expiration datetime from the JWT token.

    Raises:
        SabianaApiClientError: If token is malformed or missing 'exp' claim.

    """
    jwt_parts_count = 3
    base64_padding_mod = 4

    def _raise_value_error(message: str) -> None:
        """Raise ValueError with the given message."""
        raise ValueError(message)

    try:
        parts = token.split(".")
        if len(parts) != jwt_parts_count:
            error_msg = "Invalid JWT format: expected 3 parts"
            _raise_value_error(error_msg)

        payload_encoded = parts[1]
        padding = len(payload_encoded) % base64_padding_mod
        if padding:
            payload_encoded += "=" * (base64_padding_mod - padding)

        payload_bytes = base64.urlsafe_b64decode(payload_encoded)
        payload_str = payload_bytes.decode("utf-8")
        payload = json.loads(payload_str)

        exp_timestamp = payload.get("exp")
        if exp_timestamp is None:
            error_msg = "JWT token missing 'exp' claim"
            _raise_value_error(error_msg)

        return datetime.fromtimestamp(exp_timestamp, tz=UTC)

    except (ValueError, json.JSONDecodeError, KeyError, IndexError) as err:
        error_msg = f"Failed to extract expiry from JWT token: {err}"
        _LOGGER.exception(error_msg)
        raise SabianaApiClientError(error_msg) from err


def _create_jwt(token: str) -> JWT:
    """Create a JWT object with expiration extracted from the token's 'exp' claim.

    Args:
        token: JWT token string.

    Returns:
        JWT object with token and expiration timestamp from the JWT.

    Raises:
        SabianaApiClientError: If token is malformed or missing 'exp' claim.

    """
    expire_at = _extract_jwt_expiry(token)
    return JWT(token=token, expire_at=expire_at)


def create_jwt(token: str) -> JWT:
    """Create a JWT object from a token string, reading its 'exp' claim.

    Raises:
        SabianaApiClientError: If token is malformed or missing 'exp' claim.

    """
    return _create_jwt(token)


def extract_jwts(data: dict[str, Any]) -> tuple[JWT, JWT]:
    """Extract shortJwt and longJwt from API response.

    Args:
        data: API response data dictionary.

    Returns:
        Tuple of (shortJwt, longJwt) as JWT objects.

    """
    short_jwt_token = data["body"]["user"]["shortJwt"]
    long_jwt_token = data["body"]["user"]["longJwt"]
    return (
        _create_jwt(short_jwt_token),
        _create_jwt(long_jwt_token),
    )


def extract_renewed_token(data: dict[str, Any]) -> JWT:
    """Extract newToken from renewJwt API response.

    Args:
        data: API response data dictionary.

    Returns:
        New short JWT object.

    """
    return _create_jwt(data["body"]["newToken"])


def extract_rotated_token(data: dict[str, Any]) -> str | None:
    """Return the new long JWT carried by a successful response, if any.

    The app stores any "token" longer than 10 characters found next to
    "status": 0 as its new long JWT (checkResponse).
    """
    token = data.get("token")
    if (
        data.get("status", 0) == 0
        and isinstance(token, str)
        and len(token) > _MIN_ROTATED_TOKEN_LENGTH
    ):
        return token
    return None


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _optional_int(value: object) -> int | None:
    """Convert a JSON number (or numeric string) to int, like Number() in JS."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(float(value))
        except ValueError:
            return None
    return None


def parse_device(raw: dict[str, Any]) -> SabianaDevice:
    """Build a SabianaDevice from one entry of getDeviceForUserV2 body.devices.

    lastData is decoded with the decoder chosen by deviceStateModelType, as
    the app does in manageDevicesList / createCorrectUnitDataModel.
    """
    device_id = str(raw["idDevice"])
    model_type = _optional_str(raw.get("deviceStateModelType")) or ""
    last_data = _optional_str(raw.get("lastData"))

    # RVU frames have a different layout and are not decoded yet.
    state, data_valid = decode_device_data(model_type, last_data)

    connection_up = raw.get("connectionUp")
    return SabianaDevice(
        id=device_id,
        name=_optional_str(raw.get("deviceName")) or device_id,
        model_type=model_type,
        group_id=_optional_str(raw.get("deviceGroupId")),
        group_name=_optional_str(raw.get("deviceGroupName")),
        group_shared=bool(raw.get("deviceGroupShared")),
        from_share=bool(raw.get("fromShare")),
        from_group_share=bool(raw.get("fromGroupShare")),
        connection_up=None if connection_up is None else bool(connection_up),
        wifi_fw=_optional_str(raw.get("deviceStateFw")),
        wifi_rssi=_optional_int(raw.get("deviceWiFiRSSI")),
        fw_update_request=_optional_str(raw.get("fwUpdateRequest")),
        time_zone=_optional_str(raw.get("deviceTimeZone")),
        last_data=last_data,
        data_valid=data_valid,
        state=state,
    )


def parse_device_list(data: dict[str, Any]) -> SabianaDeviceList:
    """Parse a validated getDeviceForUserV2 response.

    Body: {"devices": [...], "lastFw": [{"type": "evo", "version": "1.23"}]}.
    Devices are sorted by idDevice, like the app.

    Raises:
        SabianaApiClientError: If the body does not have the shape the app
            relies on (manageDevicesList fails on it and keeps the previous
            list). An empty device list is valid.

    """
    body = data.get("body")
    raw_devices = body.get("devices") if isinstance(body, dict) else None
    raw_last_fw = body.get("lastFw") if isinstance(body, dict) else None
    if (
        not isinstance(raw_devices, list)
        or not isinstance(raw_last_fw, list)
        or not all(
            isinstance(d, dict) and isinstance(d.get("idDevice"), str) and d["idDevice"]
            for d in raw_devices
        )
        or not all(isinstance(item, dict) for item in raw_last_fw)
    ):
        msg = f"Malformed getDeviceForUserV2 response: {body!r}"
        raise SabianaApiClientError(msg)

    devices: dict[str, SabianaDevice] = {}
    for raw in sorted(raw_devices, key=lambda d: d["idDevice"]):
        device = parse_device(raw)
        devices[device.id] = device
        _LOGGER.debug(
            "Device %s (%s): type=%s, connectionUp=%s, valid=%s, lastData=%s, state=%s",
            device.id,
            device.name,
            device.model_type,
            device.connection_up,
            device.data_valid,
            device.last_data,
            device.state,
        )

    # App: lastFirmwareVersion[type] = version, for every entry
    last_fw = {
        item["type"]: item["version"]
        for item in raw_last_fw
        if isinstance(item.get("type"), str) and isinstance(item.get("version"), str)
    }

    return SabianaDeviceList(
        devices=devices,
        last_fw=last_fw,
        rotated_token=extract_rotated_token(data),
    )


def create_session_client(hass: HomeAssistant) -> httpx.AsyncClient:
    """Create HTTP client with retry logic for Sabiana API.

    Args:
        hass: Home Assistant instance.

    Returns:
        Configured httpx AsyncClient with retry transport.

    """
    base_client = create_async_httpx_client(hass, timeout=5.0)
    retry = Retry(total=3, backoff_factor=0.5)
    base_client._transport = RetryTransport(  # noqa: SLF001
        transport=base_client._transport,  # noqa: SLF001
        retry=retry,
    )
    return base_client


async def async_authenticate(
    session: httpx.AsyncClient,
    email: str,
    password: str,
) -> tuple[JWT, JWT]:
    """Authenticate with Sabiana API using email and password.

    Args:
        session: HTTP client session.
        email: User email address.
        password: User password.

    Returns:
        Tuple of (shortJwt, longJwt) as JWT objects.

    Raises:
        SabianaApiAuthError: If authentication fails.
        SabianaApiClientError: If API request fails.

    """
    url = f"{BASE_URL}/users/newLogin"
    payload = {"email": email, "password": password, "device": "ios"}
    headers = create_headers()

    _LOGGER.debug("Authenticating with Sabiana API")
    response = await session.post(url, headers=headers, json=payload)
    data = validate_response(response)
    short_jwt, long_jwt = extract_jwts(data)
    _LOGGER.debug("Successfully authenticated with Sabiana API")
    return (short_jwt, long_jwt)


async def async_get_devices(
    session: httpx.AsyncClient,
    short_jwt: str,
) -> SabianaDeviceList:
    """Fetch the devices of the account (GET devices/getDeviceForUserV2).

    Args:
        session: HTTP client session.
        short_jwt: Short-term JWT.

    Returns:
        The parsed device list, with lastFw and the rotated long JWT, if any.

    Raises:
        SabianaApiAuthError: If authentication fails.
        SabianaApiClientError: If API request fails.

    """
    url = f"{BASE_URL}/devices/getDeviceForUserV2"
    headers = create_headers(short_jwt)

    _LOGGER.debug("Fetching devices from Sabiana API")
    response = await session.get(url, headers=headers)
    data = validate_response(response)
    device_list = parse_device_list(data)
    _LOGGER.debug("Retrieved %d devices from Sabiana API", len(device_list.devices))
    return device_list


async def async_renew_jwt(session: httpx.AsyncClient, long_jwt: str) -> JWT:
    """Renew short-term JWT using long-term JWT.

    Args:
        session: HTTP client session.
        long_jwt: Long-term JWT used for renewal.

    Returns:
        New short JWT object.

    Raises:
        SabianaApiAuthError: If authentication fails.
        SabianaApiClientError: If API request fails.

    """
    url = f"{BASE_URL}/renewJwt"
    headers = create_headers_renew(long_jwt)
    payload = {}

    _LOGGER.debug("Renewing JWT with Sabiana API")
    response = await session.post(url, headers=headers, json=payload)
    data = validate_response(response)
    _LOGGER.debug("Successfully renewed JWT with Sabiana API")
    return extract_renewed_token(data)


async def async_send_command(
    session: httpx.AsyncClient,
    short_jwt: str,
    device_id: str,
    data: str,
) -> dict[str, Any]:
    """Send a fancoil command (POST devices/cmd, start 2304).

    "status": 0 only means the cloud accepted the command, not that the
    device applied it: the app waits for the next "data" event to know.

    Args:
        session: HTTP client session.
        short_jwt: Short-term JWT.
        device_id: Target device identifier (idDevice).
        data: The 5 registers, as built by FancoilCommand.to_hex.

    Returns:
        The validated response, which may carry a rotated long JWT.

    Raises:
        SabianaApiAuthError: If authentication fails.
        SabianaApiClientError: If API request fails.

    """
    url = f"{BASE_URL}/devices/cmd"
    headers = create_headers(short_jwt)
    payload = {
        "deviceID": device_id,
        "start": COMMAND_START,
        "data": data,
        "restart": False,
    }

    _LOGGER.debug("Sending command to device %s: %s", device_id, data)
    response = await session.post(url, headers=headers, json=payload)
    response_data = validate_response(response)
    _LOGGER.debug("Command accepted by the cloud for device %s", device_id)
    return response_data
