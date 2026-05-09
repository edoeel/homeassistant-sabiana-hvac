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

DEFAULT_POLL_INTERVAL = 120  # Fallback when WebSocket is disconnected
WS_CONNECTED_POLL_INTERVAL = 1800  # 30 minutes when WebSocket handles real-time
WEBSOCKET_RECONNECT_DELAY = 5  # Initial seconds to wait before reconnecting
WEBSOCKET_MAX_RECONNECT_DELAY = 300  # Max 5 minutes between reconnect attempts

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
    HVACMode.COOL: "0",      # MODE_SUMMER
    HVACMode.HEAT: "1",      # MODE_WINTER
    HVACMode.AUTO: "2",      # MODE_AUTO
    HVACMode.FAN_ONLY: "3",  # MODE_FAN_ONLY
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

# Mapping from device flap position byte value to swing mode name.
# The device reports flap position as an integer (0-4) at byte 8,
# with a presence flag at byte 9.
# Position 0 ("Standard") has no matching swing mode — treated as no change.
FLAP_POSITION_TO_SWING_MODE: dict[int, str] = {
    1: "Horizontal",   # Summer position
    2: "45 Degrees",   # Winter position
    3: "Vertical",     # All open
    4: "Swing",        # Oscillating
}

# Raw HVAC mode byte values to setpoint byte positions.
# Each mode stores its target temperature in a different Modbus register:
#   Summer/Cool (0) → word 7 = bytes 12-13
#   Winter/Heat (1) → word 8 = bytes 14-15
#   Auto        (2) → word 9 = bytes 16-17
MODE_SETPOINT_BYTES: dict[int, tuple[int, int]] = {
    0: (12, 13),  # Summer / Cool
    1: (14, 15),  # Winter / Heat
    2: (16, 17),  # Auto
}
