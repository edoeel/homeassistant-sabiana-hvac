"""API client for Sabiana HVAC systems.

This module provides functions to interact with the Sabiana API,
including authentication, device management, and command sending.
"""

import base64
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx
from homeassistant.core import HomeAssistant
from homeassistant.helpers.httpx_client import create_async_httpx_client
from httpx_retries import Retry, RetryTransport

from .const import BASE_URL, USER_AGENT
from .models import JWT, SabianaDeviceState

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
    """Represents a Sabiana HVAC device.

    Attributes:
        id: Unique device identifier.
        name: Human-readable device name.

    """

    id: str
    name: str


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


def extract_devices(data: dict[str, Any]) -> list[SabianaDevice]:
    """Extract device list from API response.

    Args:
        data: API response data dictionary.

    Returns:
        List of SabianaDevice objects.

    """
    devices_data = data.get("body", {}).get("devices", [])
    return [SabianaDevice(id=d["idDevice"], name=d["deviceName"]) for d in devices_data]


def decode_last_data(hex_string: str) -> SabianaDeviceState:
    """Decode the lastData hex string into a SabianaDeviceState.

    Byte Structure:
        Bytes 1-2:  Controller model (hex)
        Byte 4:     Fan mode
        Byte 5:     HVAC mode (lower nibble)
        Byte 6:     Flags (swing on bit 0)
        Byte 7:     Power state (lower nibble) and Sleep mode (upper nibble = 0xE)
        Byte 11:    Current temperature * 10
        Bytes 14-15: Target temperature * 10 (big-endian)

    Returns:
        SabianaDeviceState with decoded values or None values if decoding fails.

    """
    # Constants for decoding
    min_data_length = 16

    # Byte indices
    byte_fan_mode = 4
    byte_hvac_mode = 5
    byte_flags = 6
    byte_power_sleep = 7
    byte_current_temp = 11
    byte_target_temp_high = 14
    byte_target_temp_low = 15

    # Bit masks
    mask_swing_bit = 0x01

    try:
        data = bytes.fromhex(hex_string)

        # Validate minimum data length
        if len(data) < min_data_length:
            _LOGGER.warning(
                "lastData too short: %d bytes (minimum %d required)",
                len(data),
                min_data_length,
            )
            return _create_empty_device_state(hex_string)

        # Decode controller model (bytes 1-2)
        controller_model = _decode_controller_model(data)

        # Decode temperatures
        current_temp = _decode_current_temperature(data[byte_current_temp])
        target_temp = _decode_target_temperature(
            data[byte_target_temp_high], data[byte_target_temp_low]
        )

        # Decode HVAC mode and power state
        hvac_mode, power_on = _decode_hvac_mode_and_power(
            data[byte_hvac_mode], data[byte_power_sleep]
        )

        # Decode fan mode (byte 4)
        fan_mode = _decode_fan_mode(data[byte_fan_mode])

        # Decode sleep/preset mode from status flags
        preset_mode = _decode_preset_mode(data[byte_power_sleep])

        # Decode swing mode (byte 6 bit 0)
        swing_mode = "on" if data[byte_flags] & mask_swing_bit else "off"

        return SabianaDeviceState(
            hvac_mode=hvac_mode,
            target_temperature=target_temp,
            current_temperature=current_temp,
            fan_mode=fan_mode,
            swing_mode=swing_mode,
            preset_mode=preset_mode,
            power_on=power_on,
            controller_model=controller_model,
            raw_state={"lastData": hex_string, "decoded_bytes": list(data)},
        )

    except (ValueError, IndexError):
        _LOGGER.exception("Failed to decode lastData")
        return _create_empty_device_state(hex_string, error="decode_error")


def _create_empty_device_state(
    hex_string: str, error: str | None = None
) -> SabianaDeviceState:
    """Create a SabianaDeviceState with all None values."""
    raw_state = {"lastData": hex_string}
    if error:
        raw_state["error"] = error

    return SabianaDeviceState(
        hvac_mode=None,
        target_temperature=None,
        current_temperature=None,
        fan_mode=None,
        swing_mode=None,
        preset_mode=None,
        power_on=None,
        controller_model=None,
        raw_state=raw_state,
    )


def _decode_controller_model(data: bytes) -> str:
    """Decode controller model from bytes 1-2.

    Args:
        data: Raw byte data from device.

    Returns:
        Controller model as hex string (e.g., "2000") or "UNKNOWN".

    """
    min_bytes_for_model = 2
    if len(data) > min_bytes_for_model:
        return f"{data[1]:02X}{data[2]:02X}"
    return "UNKNOWN"


def _decode_current_temperature(temp_byte: int) -> float | None:
    """Decode current temperature from byte 11.

    Args:
        temp_byte: Temperature byte value.

    Returns:
        Temperature in Celsius or None if invalid.

    """
    return temp_byte / 10.0 if temp_byte > 0 else None


def _decode_target_temperature(high_byte: int, low_byte: int) -> float | None:
    """Decode target temperature from bytes 14-15 (big-endian).

    Args:
        high_byte: High byte of temperature.
        low_byte: Low byte of temperature.

    Returns:
        Temperature in Celsius or None if invalid.

    """
    if high_byte or low_byte:
        return ((high_byte << 8) | low_byte) / 10.0
    return None


def _decode_hvac_mode_and_power(mode_byte: int, power_byte: int) -> tuple[str, bool]:
    """Decode HVAC mode and power state.

    HVAC mode is in byte 5 (lower nibble).
    Power state is determined by byte 7 (lower nibble = 0 means OFF).

    Args:
        mode_byte: Byte 5 containing HVAC mode.
        power_byte: Byte 7 containing power state.

    Returns:
        Tuple of (hvac_mode, power_on).

    """
    # HVAC mode mapping (byte 5 lower nibble)
    hvac_mode_map = {
        0x00: "cool",  # MODE_SUMMER
        0x01: "heat",  # MODE_WINTER
        0x02: "heat_cool",  # MODE_AUTO
        0x03: "fan_only",  # MODE_FAN_ONLY
    }

    mode_nibble = mode_byte & 0x0F
    hvac_mode = hvac_mode_map.get(mode_nibble, "heat")

    # Check power state (byte 7 lower nibble = 0 means OFF)
    power_nibble = power_byte & 0x0F
    if power_nibble == 0x00:
        hvac_mode = "off"
        power_on = False
    else:
        power_on = True

    return hvac_mode, power_on


def _decode_fan_mode(fan_byte: int) -> str:
    """Decode fan mode from byte 4.

    Verified mappings from actual device testing:
    - 0x04: AUTO
    - 0x14: LOW
    - 0x3C: MEDIUM
    - 0x6E: HIGH

    Args:
        fan_byte: Byte 4 value.

    Returns:
        Fan mode string (low, medium, high, auto).

    """
    fan_mode_map = {
        0x04: "auto",
        0x14: "low",
        0x1C: "low",  # Alternate encoding
        0x3C: "medium",
        0x4C: "medium",  # Alternate encoding
        0x6E: "high",
        0x7E: "high",  # Alternate encoding
    }

    fan_mode = fan_mode_map.get(fan_byte)

    if fan_mode is None:
        _LOGGER.warning("Unknown fan mode byte: 0x%02X, defaulting to auto", fan_byte)
        return "auto"

    return fan_mode


def _decode_preset_mode(power_sleep_byte: int) -> str:
    """Decode preset/sleep mode from device status flags.

    Args:
        power_sleep_byte: Byte 7 value.

    Returns:
        Preset mode string ("sleep" or "none").

    """
    if power_sleep_byte & 0x80:
        return "sleep"

    return "none"


def extract_device_states_from_devices(
    data: dict[str, Any],
) -> dict[str, SabianaDeviceState]:
    """Extract device states from getDeviceForUserV2 response by decoding lastData."""
    devices = data.get("body", {}).get("devices", [])
    states = {}

    for device in devices:
        device_id = str(device.get("idDevice", ""))
        device_name = str(device.get("deviceName", ""))
        last_data = device.get("lastData", "")

        if device_id and last_data:
            states[device_id] = decode_last_data(last_data)
            _LOGGER.debug(
                "Decoded state for device id %s and name %s: %s",
                device_id,
                device_name,
                states[device_id],
            )

    return states


def extract_result(data: dict[str, Any]) -> bool:
    """Extract result status from API response.

    Args:
        data: API response data dictionary.

    Returns:
        True if operation was successful, False otherwise.

    """
    return data.get("body", {}).get("result", False)


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
) -> list[SabianaDevice]:
    """Fetch user devices from Sabiana API.

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
) -> bool:
    """Send command to Sabiana device.

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
