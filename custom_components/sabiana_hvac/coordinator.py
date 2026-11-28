# Copyright (c) 2026 Edoardo Mistretta

"""Coordinator for Sabiana HVAC integration."""

from __future__ import annotations

import logging
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import httpx
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from . import api
from .const import (
    CONF_LONG_JWT,
    CONF_LONG_JWT_EXPIRE_AT,
    CONF_SHORT_JWT,
    CONF_SHORT_JWT_EXPIRE_AT,
    DOMAIN,
)
from .models import JWT, SabianaDevice
from .protocol import decode_device_data

if TYPE_CHECKING:
    from collections.abc import Callable

    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant

    from .websocket import (
        SabianaWebSocketManager,
        WebSocketConnectionEvent,
        WebSocketDeviceUpdate,
        WebSocketStatusEvent,
    )

_LOGGER = logging.getLogger(__name__)

# Secrets never written to the logs
_REDACTED_KEYS = frozenset({CONF_PASSWORD, CONF_SHORT_JWT, CONF_LONG_JWT})


class SabianaTokenCoordinator(DataUpdateCoordinator[str]):
    """Coordinator to manage Sabiana JWT tokens with automatic refresh."""

    def __init__(
        self,
        hass: HomeAssistant,
        session: httpx.AsyncClient,
        config_entry: ConfigEntry,
    ) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=60),
            config_entry=config_entry,
        )
        self.session = session
        self.config_entry = config_entry
        self.data = self.short_jwt.token

    @property
    def short_jwt(self) -> JWT:
        """Get the current short JWT from config entry."""
        return JWT(
            token=self.config_entry.data[CONF_SHORT_JWT],
            expire_at=datetime.fromtimestamp(
                self.config_entry.data[CONF_SHORT_JWT_EXPIRE_AT],
                UTC,
            ),
        )

    @property
    def long_jwt(self) -> JWT:
        """Get the current long JWT from config entry."""
        return JWT(
            token=self.config_entry.data[CONF_LONG_JWT],
            expire_at=datetime.fromtimestamp(
                self.config_entry.data[CONF_LONG_JWT_EXPIRE_AT],
                UTC,
            ),
        )

    async def _async_update_data(self) -> str:
        """Check token expiration and refresh if needed.

        Uses a safety margin to refresh tokens before they actually expire,
        preventing race conditions where commands fail with auth errors
        between coordinator refresh cycles.
        """
        now = datetime.now(UTC)
        token_refresh_margin = timedelta(minutes=5)

        if now >= (self.long_jwt.expire_at - token_refresh_margin):
            _LOGGER.warning(
                "Long JWT expired or expiring soon, performing full re-authentication"
            )
            short_jwt, long_jwt = await self._async_reauth()
            self._update_tokens(short_jwt, long_jwt)
            return short_jwt.token

        if now >= (self.short_jwt.expire_at - token_refresh_margin):
            _LOGGER.debug(
                "Short JWT expired or expiring soon, refreshing using long JWT"
            )
            try:
                new_short_jwt = await api.async_renew_jwt(
                    self.session,
                    self.long_jwt.token,
                )
            except api.SabianaApiAuthError as err:
                _LOGGER.warning(
                    "Long JWT expired or invalid, attempting automatic "
                    "re-authentication: %s",
                    err,
                )
                short_jwt, long_jwt = await self._async_reauth()
                self._update_tokens(short_jwt, long_jwt)
                return short_jwt.token
            except api.SabianaApiClientError as err:
                error_msg = f"API error: {err}"
                _LOGGER.exception("API error during token refresh")
                raise UpdateFailed(error_msg) from err
            except httpx.RequestError as err:
                error_msg = f"Connection error: {err}"
                _LOGGER.exception("Connection error during token refresh")
                raise UpdateFailed(error_msg) from err
            else:
                self._update_tokens(new_short_jwt)
                _LOGGER.info("Successfully refreshed short JWT token")
                return new_short_jwt.token

        _LOGGER.debug(
            "Tokens still valid, no refresh needed. "
            "Short JWT expires at: %s, Long JWT expires at: %s",
            self.short_jwt.expire_at.isoformat(),
            self.long_jwt.expire_at.isoformat(),
        )
        _LOGGER.debug(
            "Config entry data: %s",
            {
                key: "**REDACTED**" if key in _REDACTED_KEYS else value
                for key, value in self.config_entry.data.items()
            },
        )
        return self.short_jwt.token

    async def _async_reauth(self) -> tuple[JWT, JWT]:
        """Perform full re-authentication and return both JWT objects.

        Called automatically when the long JWT has expired.

        Returns:
            A tuple containing (short_jwt, long_jwt) as JWT objects.

        Raises:
            UpdateFailed: If credentials are missing or authentication fails.

        """
        email = self.config_entry.data.get(CONF_EMAIL)
        password = self.config_entry.data.get(CONF_PASSWORD)

        if not email or not password:
            error_msg = (
                "Email or password not found in config entry. Cannot auto-refresh."
            )
            _LOGGER.error(error_msg)
            raise UpdateFailed(error_msg)

        try:
            _LOGGER.info("Performing automatic re-authentication with email: %s", email)
            short_jwt, long_jwt = await api.async_authenticate(
                self.session,
                email,
                password,
            )
        except api.SabianaApiAuthError as err:
            error_msg = f"Auto re-authentication failed with stored credentials: {err}"
            _LOGGER.exception("Auto re-authentication failed")
            raise UpdateFailed(error_msg) from err
        except api.SabianaApiClientError as err:
            error_msg = f"API error during auto re-authentication: {err}"
            _LOGGER.exception("API error during auto re-authentication")
            raise UpdateFailed(error_msg) from err
        except httpx.RequestError as err:
            error_msg = f"Connection error during auto re-authentication: {err}"
            _LOGGER.exception("Connection error during auto re-authentication")
            raise UpdateFailed(error_msg) from err

        _LOGGER.info("Successfully re-authenticated and obtained new tokens")
        return short_jwt, long_jwt

    def _update_tokens(self, short_jwt: JWT, long_jwt: JWT | None = None) -> None:
        """Update tokens in config entry."""
        data = {
            **self.config_entry.data,
            CONF_SHORT_JWT: short_jwt.token,
            CONF_SHORT_JWT_EXPIRE_AT: int(short_jwt.expire_at.timestamp()),
        }

        if long_jwt is not None:
            data[CONF_LONG_JWT] = long_jwt.token
            data[CONF_LONG_JWT_EXPIRE_AT] = int(long_jwt.expire_at.timestamp())

        self.hass.config_entries.async_update_entry(self.config_entry, data=data)
        self.data = short_jwt.token

    def store_rotated_long_jwt(self, token: str) -> None:
        """Store a long JWT rotated by the server in a response envelope.

        The app saves any "token" returned with "status": 0 as its new long
        JWT (checkResponse). A token whose expiry cannot be read is ignored,
        keeping the current one.
        """
        if token == self.long_jwt.token:
            return
        try:
            long_jwt = api.create_jwt(token)
        except api.SabianaApiClientError:
            _LOGGER.warning("Ignoring rotated long JWT without a readable expiry")
            return

        data = {
            **self.config_entry.data,
            CONF_LONG_JWT: long_jwt.token,
            CONF_LONG_JWT_EXPIRE_AT: int(long_jwt.expire_at.timestamp()),
        }
        self.hass.config_entries.async_update_entry(self.config_entry, data=data)
        _LOGGER.info(
            "Stored rotated long JWT, expires at %s", long_jwt.expire_at.isoformat()
        )

    async def async_force_renew(self) -> str:
        """Force an unconditional token renewal, bypassing expiry checks.

        Used when the server has rejected a token that locally appears valid
        (e.g., server-side revocation or early expiry).

        Returns:
            The new short JWT token string.

        Raises:
            UpdateFailed: If renewal fails.

        """
        _LOGGER.debug("Forcing unconditional token renewal")
        try:
            new_short_jwt = await api.async_renew_jwt(
                self.session,
                self.long_jwt.token,
            )
        except api.SabianaApiAuthError:
            _LOGGER.warning(
                "Long JWT also rejected during force renew, "
                "attempting full re-authentication"
            )
            short_jwt, long_jwt = await self._async_reauth()
            self._update_tokens(short_jwt, long_jwt)
            return short_jwt.token
        except api.SabianaApiClientError as err:
            error_msg = f"API error during force renew: {err}"
            raise UpdateFailed(error_msg) from err
        except httpx.RequestError as err:
            error_msg = f"Connection error during force renew: {err}"
            raise UpdateFailed(error_msg) from err

        self._update_tokens(new_short_jwt)
        _LOGGER.info("Force-renewed short JWT token")
        return new_short_jwt.token


class SabianaDeviceCoordinator(DataUpdateCoordinator[dict[str, SabianaDevice]]):
    """Coordinator that owns the device list of the account.

    The data is the parsed getDeviceForUserV2 list, keyed by idDevice, as
    the app keeps it: REST reads replace it and Socket.IO events update single
    devices in place (data, connEvents, status). There is no polling.
    """

    def __init__(
        self,
        hass: HomeAssistant,
        session: httpx.AsyncClient,
        token_coordinator: SabianaTokenCoordinator,
        config_entry: ConfigEntry,
        websocket_manager: SabianaWebSocketManager | None = None,
    ) -> None:
        """Initialize the device coordinator.

        Args:
            hass: Home Assistant instance.
            session: HTTP client session.
            token_coordinator: Token coordinator for JWT management.
            config_entry: Config entry the devices belong to.
            websocket_manager: Optional WebSocket manager for real-time updates.

        """
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_devices",
            # No periodic polling, as in the app: the list is read at setup,
            # on every reconnection of the socket and on appMsg "refresh".
            update_interval=None,
            config_entry=config_entry,
            # Records are frozen dataclasses: skip listener updates when a
            # REST read returns exactly what we already have.
            always_update=False,
        )
        self._session = session
        self._token_coordinator = token_coordinator
        self._websocket_manager = websocket_manager
        self._device_ids: frozenset[str] | None = None
        self._unsubscribe_callbacks: list[Callable[[], None]] = []
        self.last_fw: dict[str, str] = {}
        self.data = {}

        # Register for WebSocket updates if manager is available
        if self._websocket_manager is not None:
            self._setup_websocket_callbacks()

    @property
    def realtime_connected(self) -> bool:
        """Return whether the Socket.IO channel is up (data events arrive)."""
        return self._websocket_manager is not None and self._websocket_manager.connected

    @property
    def device_ids(self) -> frozenset[str]:
        """Return the ids of the devices of the account."""
        return self._device_ids or frozenset()

    def _setup_websocket_callbacks(self) -> None:
        """Set up callbacks for WebSocket events."""
        if self._websocket_manager is None:
            return

        ws = self._websocket_manager
        self._unsubscribe_callbacks.extend(
            [
                ws.register_device_update_callback(self._handle_ws_data),
                ws.register_connection_event_callback(self._handle_ws_conn_event),
                ws.register_status_callback(self._handle_ws_status),
                ws.register_refresh_callback(self._handle_ws_refresh),
                ws.register_connection_status_callback(
                    self._handle_ws_connection_status
                ),
            ]
        )

    def _set_device(self, device: SabianaDevice) -> None:
        """Replace one device record and notify the entities."""
        self.async_set_updated_data({**self.data, device.id: device})

    def _handle_ws_data(self, update: WebSocketDeviceUpdate) -> None:
        """Apply a "data" event: new lastData, and the device is online.

        App: cloudDevicesDataUpdates. A frame forces connectionUp to true;
        an unchanged frame on an online device changes nothing.
        """
        device = self.data.get(update.device_id)
        if device is None:
            _LOGGER.debug("Data event for unknown device %s", update.device_id)
            return
        if update.data == device.last_data and device.connection_up:
            return

        state, data_valid = decode_device_data(
            device.model_type, update.data, previous=device.state
        )
        if not data_valid:
            _LOGGER.warning("Device %s sent invalid data: %s", device.id, update.data)
        if not device.connection_up:
            _LOGGER.debug("Data from device %s, forcing it online", device.id)

        self._set_device(
            replace(
                device,
                last_data=update.data,
                state=state,
                data_valid=data_valid,
                connection_up=True,
            )
        )

    def _handle_ws_conn_event(self, event: WebSocketConnectionEvent) -> None:
        """Apply a "connEvents" event (app: cloudDevicesConnEventUpdates)."""
        device = self.data.get(event.device_id)
        if device is None or device.connection_up == event.connected:
            return
        self._set_device(replace(device, connection_up=event.connected))

    def _handle_ws_status(self, event: WebSocketStatusEvent) -> None:
        """Apply a "status" event (app: cloudDevicesStateUpdates)."""
        device = self.data.get(event.device_id)
        if device is None:
            return
        updated = replace(device, wifi_fw=event.wifi_fw, wifi_rssi=event.wifi_rssi)
        if updated != device:
            self._set_device(updated)

    def _handle_ws_refresh(self) -> None:
        """Re-read the device list when the server asks for it."""
        _LOGGER.debug("Server requested refresh, triggering immediate update")
        self.hass.async_create_task(self.async_request_refresh())

    def _handle_ws_connection_status(self, *, connected: bool) -> None:
        """Notify the entities: without the socket the cloud is offline.

        App: isCloudOnLine follows the socket and blocks every control while
        it is down; no REST fallback is used.
        """
        _LOGGER.info(
            "Sabiana cloud %s",
            "online" if connected else "offline until the WebSocket reconnects",
        )
        self.async_update_listeners()

    async def _async_update_data(self) -> dict[str, SabianaDevice]:
        """Read the device list (GET devices/getDeviceForUserV2).

        Called only when the app reads it: at setup, after every reconnection
        of the socket and when the server sends appMsg "refresh".
        """
        await self._token_coordinator.async_request_refresh()

        try:
            device_list = await api.async_get_devices(
                self._session, self._token_coordinator.short_jwt.token
            )
        except api.SabianaApiAuthError as err:
            msg = f"Authentication error while reading devices: {err}"
            raise UpdateFailed(msg) from err
        except api.SabianaApiClientError as err:
            msg = f"API error while reading devices: {err}"
            raise UpdateFailed(msg) from err
        except httpx.RequestError as err:
            msg = f"Connection error while reading devices: {err}"
            raise UpdateFailed(msg) from err

        if device_list.rotated_token:
            self._token_coordinator.store_rotated_long_jwt(device_list.rotated_token)

        self.last_fw = device_list.last_fw
        self._check_device_list_changed(device_list.devices)
        _LOGGER.debug("Read %d devices", len(device_list.devices))
        return device_list.devices

    def _check_device_list_changed(self, devices: dict[str, SabianaDevice]) -> None:
        """Reload the entry when devices are added to or removed from the account.

        The app rebuilds its list (and refreshes the socket subscription) when
        the set of idDevice changes; here entities are created at setup, so a
        reload is needed to follow the change.
        """
        device_ids = frozenset(devices)
        if self._device_ids is None or device_ids == self._device_ids:
            self._device_ids = device_ids
            return

        _LOGGER.info(
            "Device list changed (added: %s, removed: %s), reloading the integration",
            sorted(device_ids - self._device_ids),
            sorted(self._device_ids - device_ids),
        )
        self._device_ids = device_ids
        if self.config_entry is not None:
            self.hass.config_entries.async_schedule_reload(self.config_entry.entry_id)

    async def async_shutdown(self) -> None:
        """Clean up when the coordinator is being shut down."""
        for unsubscribe in self._unsubscribe_callbacks:
            unsubscribe()
        self._unsubscribe_callbacks.clear()

        await super().async_shutdown()
