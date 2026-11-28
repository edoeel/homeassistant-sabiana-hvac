# Copyright (c) 2026 Edoardo Mistretta

"""Constants for Sabiana HVAC integration.

This module contains all the constants used throughout the integration,
including API endpoints, configuration keys, and mapping dictionaries.
"""

DOMAIN = "sabiana_hvac"

BASE_URL = "https://be-standard.sabianawm.cloud"
WEBSOCKET_URL = "https://be-flex.sabianawm.cloud"
USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 11; IN2013) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/93.0.4577.82 Mobile Safari/537.36"
)

# Reconnection of the Socket.IO channel. The app retries every 1-5 s; here the
# delay grows to one minute so the Sabiana backend is never flooded.
WEBSOCKET_RECONNECT_DELAY = 5  # Initial seconds to wait before reconnecting
WEBSOCKET_MAX_RECONNECT_DELAY = 60  # Max seconds between reconnect attempts
WEBSOCKET_RECONNECT_JITTER = 0.5  # Delay randomized by +/-50%, as in the app
# The delay goes back to the initial value only after a connection lasted this
# long, so a server that accepts and drops at once is not hammered.
WEBSOCKET_STABLE_CONNECTION = 60

ERROR_INVALID_AUTH = "invalid_auth"
ERROR_CANNOT_CONNECT = "cannot_connect"
ERROR_TIMEOUT = "timeout_error"
ERROR_API_ERROR = "api_error"
ERROR_UNKNOWN = "unknown_error"

CONF_SHORT_JWT = "short_jwt"
CONF_SHORT_JWT_EXPIRE_AT = "short_jwt_expire_at"
CONF_LONG_JWT = "long_jwt"
CONF_LONG_JWT_EXPIRE_AT = "long_jwt_expire_at"

# Swing modes of the climate entity, by flap position (word 5, high byte).
# App labels: 0 "Stop swing", 1 "Summer", 2 "Winter", 3 "Full open", 4 "Swing";
# positions 1-3 keep the names used since the first release of the integration.
FLAP_POSITION_TO_SWING_MODE: dict[int, str] = {
    0: "Stop swing",
    1: "Horizontal",  # Summer position
    2: "45 Degrees",  # Winter position
    3: "Vertical",  # Full open
    4: "Swing",  # Oscillating
}
SWING_MODE_TO_FLAP_POSITION = {
    name: position for position, name in FLAP_POSITION_TO_SWING_MODE.items()
}
# TMB units only have "Stop swing" and "Swing" (flapSimpleMode)
FLAP_SIMPLE_POSITIONS = (0, 4)
