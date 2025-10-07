"""
Constants for Sabiana HVAC integration.

This module contains all the constants used throughout the integration,
including API endpoints, configuration keys, and mapping dictionaries.
"""

from homeassistant.components.climate import (
    HVACMode,
)
from homeassistant.components.climate.const import (
    FAN_AUTO,
    FAN_HIGH,
    FAN_LOW,
    FAN_MEDIUM,
)

DOMAIN = "sabiana_hvac"

BASE_URL = "https://be-standard.sabianawm.cloud"
USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 11; IN2013) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/93.0.4577.82 Mobile Safari/537.36"
)

ERROR_INVALID_AUTH = "invalid_auth"
ERROR_CANNOT_CONNECT = "cannot_connect"
ERROR_TIMEOUT = "timeout_error"
ERROR_API_ERROR = "api_error"
ERROR_UNKNOWN = "unknown_error"

CONF_TOKEN = "token"  # noqa: S105

HVAC_MODE_MAP = {
    HVACMode.COOL: "0",
    HVACMode.HEAT: "1",
    HVACMode.FAN_ONLY: "3",
    HVACMode.OFF: "4",
}
FAN_MODE_MAP = {
    FAN_LOW: "1",
    FAN_MEDIUM: "2",
    FAN_HIGH: "3",
    FAN_AUTO: "4",
}
SWING_MODE_MAP = {
    "Vertical": "3",
    "Horizontal": "1",
    "45 Degrees": "2",
    "Swing": "4",
}
