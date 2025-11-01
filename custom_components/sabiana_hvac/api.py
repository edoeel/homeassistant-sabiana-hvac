"""
API client for Sabiana HVAC systems.

This module provides functions to interact with the Sabiana API,
including authentication, device management, and command sending.
"""

import logging
from dataclasses import dataclass
from typing import Any

import httpx
from homeassistant.core import HomeAssistant
from homeassistant.helpers.httpx_client import create_async_httpx_client
from httpx_retries import Retry, RetryTransport

from .const import BASE_URL, USER_AGENT

_LOGGER = logging.getLogger(__name__)

# HTTP status codes
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401


class SabianaApiClientError(Exception):
    """Base exception for Sabiana API client errors."""


class SabianaApiAuthError(SabianaApiClientError):
    """Exception raised for authentication errors."""


@dataclass(frozen=True)
class SabianaDevice:
    """
    Represents a Sabiana HVAC device.

    Attributes:
        id: Unique device identifier.
        name: Human-readable device name.

    """

    id: str
    name: str


def create_headers(short_jwt: str | None = None) -> dict[str, str]:
    """
    Create HTTP headers for Sabiana API requests.

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
    """
    Create HTTP headers for JWT renewal requests.

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
    """
    Check if HTTP status code indicates an error.

    Args:
        status: HTTP status code to check.

    Returns:
        True if status code is 400 or higher, False otherwise.

    """
    return status >= HTTP_BAD_REQUEST


def is_auth_error(status: int) -> bool:
    """
    Check if HTTP status code indicates authentication error.

    Args:
        status: HTTP status code to check.

    Returns:
        True if status code is 401, False otherwise.

    """
    return status == HTTP_UNAUTHORIZED


def is_api_error(data: dict[str, Any]) -> bool:
    """
    Check if API response indicates an error.

    Args:
        data: API response data dictionary.

    Returns:
        True if status field is not 0, False otherwise.

    """
    return data.get("status", 0) != 0


def is_auth_api_error(data: dict[str, Any]) -> bool:
    """
    Check if API response indicates authentication error.

    Args:
        data: API response data dictionary.

    Returns:
        True if status field is 99 or 103, False otherwise.

    """
    return data.get("status", 0) in [99, 103]


def validate_response(response: httpx.Response) -> dict[str, Any]:
    """
    Validate HTTP response and return parsed JSON data.

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


def extract_jwts(data: dict[str, Any]) -> tuple[str, str]:
    """
    Extract shortJwt and longJwt from API response.

    Args:
        data: API response data dictionary.

    Returns:
        Tuple of (shortJwt, longJwt).

    """
    return data["body"]["user"]["shortJwt"], data["body"]["user"]["longJwt"]


def extract_devices(data: dict[str, Any]) -> list[SabianaDevice]:
    """
    Extract device list from API response.

    Args:
        data: API response data dictionary.

    Returns:
        List of SabianaDevice objects.

    """
    devices_data = data.get("body", {}).get("devices", [])
    return [SabianaDevice(id=d["idDevice"], name=d["deviceName"]) for d in devices_data]


def extract_result(data: dict[str, Any]) -> bool:
    """
    Extract result status from API response.

    Args:
        data: API response data dictionary.

    Returns:
        True if operation was successful, False otherwise.

    """
    return data.get("body", {}).get("result", False)


def create_session_client(hass: HomeAssistant) -> httpx.AsyncClient:
    """
    Create HTTP client with retry logic for Sabiana API.

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
    session: httpx.AsyncClient, email: str, password: str
) -> tuple[str, str]:
    """
    Authenticate with Sabiana API using email and password.

    Args:
        session: HTTP client session.
        email: User email address.
        password: User password.

    Returns:
        Tuple of (shortJwt, longJwt) where:
        - shortJwt: The short-term JWT
        - longJwt: The long-term JWT

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
    session: httpx.AsyncClient, short_jwt: str
) -> list[SabianaDevice]:
    """
    Fetch user devices from Sabiana API.

    Args:
        session: HTTP client session.
        short_jwt: Short-term JWT.

    Returns:
        List of SabianaDevice objects.

    Raises:
        SabianaApiAuthError: If authentication fails.
        SabianaApiClientError: If API request fails.

    """
    url = f"{BASE_URL}/devices/getDeviceForUserV2"
    headers = create_headers(short_jwt)

    _LOGGER.debug("Fetching devices from Sabiana API")
    response = await session.get(url, headers=headers)
    data = validate_response(response)
    devices = extract_devices(data)
    _LOGGER.debug("Retrieved %d devices from Sabiana API", len(devices))
    return devices


async def async_renew_jwt(session: httpx.AsyncClient, long_jwt: str) -> str:
    """
    Renew short-term JWT using long-term JWT.

    Args:
        session: HTTP client session.
        long_jwt: Long-term JWT used for renewal.

    Returns:
        New short-term JWT.

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
    short_jwt, _ = extract_jwts(data)

    _LOGGER.debug("Successfully renewed JWT with Sabiana API")
    return short_jwt


async def async_send_command(
    session: httpx.AsyncClient, short_jwt: str, device_id: str, data: str
) -> bool:
    """
    Send command to Sabiana device.

    Args:
        session: HTTP client session.
        short_jwt: Short-term JWT.
        device_id: Target device identifier.
        data: Command data string.

    Returns:
        True if command was successful, False otherwise.

    Raises:
        SabianaApiAuthError: If authentication fails.
        SabianaApiClientError: If API request fails.

    """
    url = f"{BASE_URL}/devices/cmd"
    headers = create_headers(short_jwt)
    payload = {"deviceID": device_id, "start": 2304, "data": data, "restart": False}

    _LOGGER.debug("Sending command to device %s: %s", device_id, data)
    response = await session.post(url, headers=headers, json=payload)
    response_data = validate_response(response)
    result = extract_result(response_data)
    _LOGGER.debug("Command result for device %s: %s", device_id, result)
    return result
