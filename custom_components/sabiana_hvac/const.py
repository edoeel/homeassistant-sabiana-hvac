"""Constants for Sabiana HVAC integration.

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
WEBSOCKET_URL = "https://be-flex.sabianawm.cloud"
USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 11; IN2013) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/93.0.4577.82 Mobile Safari/537.36"
)

DEFAULT_POLL_INTERVAL = 120  # Increased since WebSocket provides real-time updates
WEBSOCKET_RECONNECT_DELAY = 5  # Seconds to wait before reconnecting

ERROR_INVALID_AUTH = "invalid_auth"
ERROR_CANNOT_CONNECT = "cannot_connect"
ERROR_TIMEOUT = "timeout_error"
ERROR_API_ERROR = "api_error"
ERROR_UNKNOWN = "unknown_error"

CONF_SHORT_JWT = "short_jwt"
CONF_SHORT_JWT_EXPIRE_AT = "short_jwt_expire_at"
CONF_LONG_JWT = "long_jwt"
CONF_LONG_JWT_EXPIRE_AT = "long_jwt_expire_at"

HVAC_MODE_MAP = {
    HVACMode.COOL: "0",
    HVACMode.HEAT: "1",
    HVACMode.DRY: "2",
    HVACMode.FAN_ONLY: "3",
    HVACMode.OFF: "4",
}
HVAC_MODE_REVERSE_MAP = {value: key for key, value in HVAC_MODE_MAP.items()}
FAN_MODE_MAP = {
    FAN_LOW: "1",  # Command "1" -> State byte 7 upper nibble 0x0
    FAN_MEDIUM: "2",  # Command "2" -> State byte 7 upper nibble 0x1
    FAN_HIGH: "3",  # Command "3" -> State byte 7 upper nibble 0x3
    FAN_AUTO: "4",  # Command "4" -> State byte 7 upper nibble 0x2
}
FAN_MODE_REVERSE_MAP = {value: key for key, value in FAN_MODE_MAP.items()}
SWING_MODE_MAP = {
    "Vertical": "3",
    "Horizontal": "1",
    "45 Degrees": "2",
    "Swing": "4",
}
SWING_MODE_REVERSE_MAP = {value: key for key, value in SWING_MODE_MAP.items()}
