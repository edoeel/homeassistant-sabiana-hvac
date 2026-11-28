# Copyright (c) 2026 Edoardo Mistretta

"""WebSocket manager for Sabiana HVAC real-time updates."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import aiohttp
import socketio

from .const import (
    WEBSOCKET_MAX_RECONNECT_DELAY,
    WEBSOCKET_RECONNECT_DELAY,
    WEBSOCKET_RECONNECT_JITTER,
    WEBSOCKET_STABLE_CONNECTION,
    WEBSOCKET_URL,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from homeassistant.core import HomeAssistant

    from .models import JWT

_LOGGER = logging.getLogger(__name__)


@dataclass
class WebSocketDeviceUpdate:
    """A "data" event: the new lastData frame of a device.

    The frame is passed undecoded: the decoder depends on the device's
    deviceStateModelType, which only the device list knows.
    """

    device_id: str
    data: str


@dataclass
class WebSocketConnectionEvent:
    """Represents a device connection event received via WebSocket."""

    device_id: str
    connected: bool


@dataclass
class WebSocketStatusEvent:
    """A "status" event: WiFi module firmware and signal of a device."""

    device_id: str
    wifi_fw: str | None
    wifi_rssi: int | None


class SabianaWebSocketManager:
    """Manager for the Sabiana Socket.IO channel (be-flex).

    Mirrors the app's cloud service: the handshake carries the short JWT in
    auth.token, every reconnection re-reads the device list (the app calls
    forceUpdateAllDevice on each "connect" after the first), and the server
    pushes data / connEvents / status / appMsg for all devices of the account.
    Reconnection is handled here, with a fresh token and exponential backoff.
    """

    def __init__(
        self,
        hass: HomeAssistant,
        get_jwt: Callable[[], JWT],
        refresh_token: Callable[[], Any] | None = None,
    ) -> None:
        """Initialize the WebSocket manager.

        Args:
            hass: Home Assistant instance.
            get_jwt: Returns the current short JWT, read at every connection.
            refresh_token: Coroutine renewing the short JWT if close to expiry.

        """
        self._hass = hass
        self._get_jwt = get_jwt
        self._refresh_token = refresh_token
        self._sio: socketio.AsyncClient | None = None
        self._http_session: aiohttp.ClientSession | None = None
        self._connected = False
        self._has_connected = False  # app: cloudInit
        self._connected_at: float | None = None
        self._handshake_jwt_expire_at: datetime | None = None
        self._reconnect_task: asyncio.Task[None] | None = None
        self._shutdown = False
        self._reconnect_delay = WEBSOCKET_RECONNECT_DELAY

        # Callbacks for different event types
        self._device_update_callbacks: list[
            Callable[[WebSocketDeviceUpdate], None]
        ] = []
        self._connection_event_callbacks: list[
            Callable[[WebSocketConnectionEvent], None]
        ] = []
        self._status_callbacks: list[Callable[[WebSocketStatusEvent], None]] = []
        self._refresh_callbacks: list[Callable[[], None]] = []
        self._connection_status_callbacks: list[Callable[[bool], None]] = []

    @property
    def connected(self) -> bool:
        """Return True if WebSocket is connected."""
        return self._connected

    def _register_callback(
        self, callback_list: list, callback: Callable
    ) -> Callable[[], None]:
        """Register a callback and return an unregister function."""
        callback_list.append(callback)

        def unregister() -> None:
            if callback in callback_list:
                callback_list.remove(callback)

        return unregister

    def register_device_update_callback(
        self,
        callback: Callable[[WebSocketDeviceUpdate], None],
    ) -> Callable[[], None]:
        """Register a callback for device state updates."""
        return self._register_callback(self._device_update_callbacks, callback)

    def register_connection_event_callback(
        self,
        callback: Callable[[WebSocketConnectionEvent], None],
    ) -> Callable[[], None]:
        """Register a callback for device connection events."""
        return self._register_callback(self._connection_event_callbacks, callback)

    def register_status_callback(
        self,
        callback: Callable[[WebSocketStatusEvent], None],
    ) -> Callable[[], None]:
        """Register a callback for device status (firmware, WiFi) events."""
        return self._register_callback(self._status_callbacks, callback)

    def register_refresh_callback(
        self,
        callback: Callable[[], None],
    ) -> Callable[[], None]:
        """Register a callback for refresh requests."""
        return self._register_callback(self._refresh_callbacks, callback)

    def register_connection_status_callback(
        self,
        callback: Callable[[bool], None],
    ) -> Callable[[], None]:
        """Register a callback for WebSocket connection status changes."""
        return self._register_callback(self._connection_status_callbacks, callback)

    async def async_connect(self) -> bool:
        """Connect to the Sabiana WebSocket server.

        If the attempt fails, reconnection attempts with backoff are scheduled,
        so the channel comes up as soon as the server is reachable.

        Returns:
            True if connection was successful, False otherwise.

        """
        connected = await self._async_try_connect()
        if not connected and not self._shutdown:
            self._schedule_reconnect()
        return connected

    async def _async_try_connect(self) -> bool:
        """Make one connection attempt.

        Refreshes the JWT token before connecting to ensure it's valid,
        especially important for reconnection attempts after long disconnections.
        """
        if self._sio is not None and self._connected:
            _LOGGER.debug("Already connected to Sabiana WebSocket")
            return True

        try:
            # Refresh token before connecting (critical for reconnections).
            # HA's async_request_refresh() swallows most exceptions internally,
            # but we guard against unexpected errors to be safe.
            if self._refresh_token is not None:
                try:
                    await self._refresh_token()
                except Exception:  # noqa: BLE001
                    _LOGGER.warning(
                        "Failed to refresh token before WebSocket connect, "
                        "using existing token"
                    )

            jwt = self._get_jwt()
            if not jwt.token:
                _LOGGER.error("Cannot connect to WebSocket: no JWT token available")
                return False

            # Clean up previous client if it exists
            if self._sio is not None:
                with contextlib.suppress(Exception):
                    await self._sio.disconnect()
                self._sio = None
            await self._async_close_http_session()

            # Force thread-based DNS resolution for this Socket.IO client.
            # This bypasses broken aiodns/pycares combinations observed in HA env.
            self._http_session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(resolver=aiohttp.ThreadedResolver())
            )

            self._sio = socketio.AsyncClient(
                reconnection=False,  # We handle reconnection ourselves
                logger=False,
                engineio_logger=False,
                http_session=self._http_session,
            )

            # Register event handlers
            self._register_event_handlers()

            _LOGGER.debug("Connecting to Sabiana WebSocket at %s", WEBSOCKET_URL)

            await self._sio.connect(
                WEBSOCKET_URL,
                auth={"token": jwt.token},
                transports=["websocket", "polling"],
            )

            self._connected = True
            self._connected_at = time.monotonic()
            self._handshake_jwt_expire_at = jwt.expire_at
            reconnected = self._has_connected
            self._has_connected = True
            _LOGGER.info("Successfully connected to Sabiana WebSocket")
            self._notify_connection_status(connected=True)
            if reconnected:
                # Events sent while the channel was down are lost: re-read the
                # whole device list, as the app does on every reconnection.
                _LOGGER.debug("WebSocket reconnected, re-reading the device list")
                self._trigger_refresh_callbacks()

        except (socketio.exceptions.ConnectionError, TimeoutError, OSError) as err:
            _LOGGER.warning("Failed to connect to Sabiana WebSocket: %s", err)
            self._connected = False
        except Exception:
            _LOGGER.exception("Unexpected error connecting to Sabiana WebSocket")
            self._connected = False

        return self._connected

    async def _async_close_http_session(self) -> None:
        """Close internal HTTP session used by Socket.IO, if any."""
        if self._http_session is not None:
            with contextlib.suppress(Exception):
                await self._http_session.close()
            self._http_session = None

    def _notify_connection_status(self, *, connected: bool) -> None:
        """Notify registered callbacks about connection status changes."""
        for callback in self._connection_status_callbacks:
            try:
                callback(connected=connected)
            except Exception:
                _LOGGER.exception("Error in connection status callback")

    def _register_event_handlers(self) -> None:
        """Register Socket.IO event handlers."""
        if self._sio is None:
            return

        @self._sio.event
        async def connect() -> None:
            """Handle successful connection."""
            _LOGGER.info("Sabiana WebSocket connected")
            self._connected = True

        @self._sio.event
        async def disconnect(reason: str | None = None) -> None:
            """Handle disconnection."""
            self._log_disconnect(reason)
            self._connected = False
            self._notify_connection_status(connected=False)
            # Schedule reconnection with backoff
            if not self._shutdown:
                self._schedule_reconnect()

        @self._sio.on("data")
        async def on_data(data: dict[str, Any]) -> None:
            """Handle device data updates.

            Event format: { device: "deviceId", data: "hexString" }
            """
            await self._handle_data_event(data)

        @self._sio.on("connEvents")
        async def on_conn_events(data: dict[str, Any]) -> None:
            """Handle device connection events.

            Event format: { device: "deviceId", data: "CONNECT" | "DISCONNECT" }
            """
            await self._handle_connection_event(data)

        @self._sio.on("status")
        async def on_status(data: dict[str, Any]) -> None:
            """Handle device status updates.

            Event format: { device: "deviceId", deviceStateFw: "x.xx",
                           deviceWiFiRSSI: -xx }
            """
            await self._handle_status_event(data)

        @self._sio.on("appMsg")
        async def on_app_msg(data: dict[str, Any]) -> None:
            """Handle application messages.

            Event format: { msg: "refresh" }
            """
            if isinstance(data, dict) and data.get("msg") == "refresh":
                _LOGGER.debug("Received refresh request from server")
                for callback in self._refresh_callbacks:
                    try:
                        callback()
                    except Exception:
                        _LOGGER.exception("Error in refresh callback")

        @self._sio.on("error")
        async def on_error(data: dict[str, Any]) -> None:
            """Handle error events."""
            _LOGGER.error("Sabiana WebSocket error: %s", data)

    def _update_backoff_after_disconnect(self, duration: float | None) -> None:
        """Reset the backoff after a stable connection, else keep growing it."""
        if duration is not None and duration >= WEBSOCKET_STABLE_CONNECTION:
            self._reconnect_delay = WEBSOCKET_RECONNECT_DELAY
        else:
            _LOGGER.debug("Short-lived WebSocket connection, backing off")
            self._increase_backoff()

    def _increase_backoff(self) -> None:
        self._reconnect_delay = min(
            self._reconnect_delay * 2, WEBSOCKET_MAX_RECONNECT_DELAY
        )

    def _log_disconnect(self, reason: str | None) -> None:
        """Log why and when the channel dropped.

        The cause of the periodic disconnections is not known (JWT expiry,
        inactivity, server close): log the reason with the connection
        duration and the expiry of the JWT used in the handshake.
        """
        duration = (
            time.monotonic() - self._connected_at
            if self._connected_at is not None
            else None
        )
        jwt_left = (
            (self._handshake_jwt_expire_at - datetime.now(UTC)).total_seconds()
            if self._handshake_jwt_expire_at is not None
            else None
        )
        self._connected_at = None
        self._update_backoff_after_disconnect(duration)
        _LOGGER.info(
            "Sabiana WebSocket disconnected (reason: %s) after %s; handshake JWT %s",
            reason,
            f"{duration:.0f}s" if duration is not None else "an unknown time",
            (
                "expiry unknown"
                if jwt_left is None
                else f"expires in {jwt_left:.0f}s"
                if jwt_left >= 0
                else f"expired {-jwt_left:.0f}s ago"
            ),
        )

    async def _handle_data_event(self, data: dict[str, Any]) -> None:
        """Process a device data update event."""
        if not isinstance(data, dict):
            _LOGGER.warning("Invalid data event received: %s", data)
            return
        device_id = data.get("device")
        hex_data = data.get("data")

        if not device_id or not hex_data:
            _LOGGER.warning("Invalid data event received: %s", data)
            return

        _LOGGER.debug(
            "Received device update via WebSocket: device=%s, data=%s",
            device_id,
            hex_data,
        )

        update = WebSocketDeviceUpdate(device_id=device_id, data=hex_data)
        for callback in self._device_update_callbacks:
            try:
                callback(update)
            except Exception:
                _LOGGER.exception("Error in device update callback")

    async def _handle_status_event(self, data: dict[str, Any]) -> None:
        """Process a device status event (firmware and WiFi signal)."""
        _LOGGER.debug("Received status update: %s", data)
        device_id = data.get("device") if isinstance(data, dict) else None
        if not device_id:
            _LOGGER.warning("Invalid status event received: %s", data)
            return

        wifi_fw = data.get("deviceStateFw")
        wifi_rssi = data.get("deviceWiFiRSSI")
        event = WebSocketStatusEvent(
            device_id=device_id,
            wifi_fw=wifi_fw if isinstance(wifi_fw, str) else None,
            wifi_rssi=(
                int(wifi_rssi)
                if isinstance(wifi_rssi, (int, float))
                and not isinstance(wifi_rssi, bool)
                else None
            ),
        )
        for callback in self._status_callbacks:
            try:
                callback(event)
            except Exception:
                _LOGGER.exception("Error in status callback")

    async def _handle_connection_event(self, data: dict[str, Any]) -> None:
        """Process a device connection event."""
        if not isinstance(data, dict):
            _LOGGER.warning("Invalid connection event received: %s", data)
            return
        device_id = data.get("device")
        event_data = data.get("data")

        if not device_id or not event_data:
            _LOGGER.warning("Invalid connection event received: %s", data)
            return

        connected = event_data == "CONNECT"
        _LOGGER.info(
            "Device %s %s",
            device_id,
            "connected" if connected else "disconnected",
        )

        event = WebSocketConnectionEvent(device_id=device_id, connected=connected)

        for callback in self._connection_event_callbacks:
            try:
                callback(event)
            except Exception:
                _LOGGER.exception("Error in connection event callback")

    def _schedule_reconnect(self) -> None:
        """Schedule a reconnection attempt with exponential backoff."""
        if self._reconnect_task is not None and not self._reconnect_task.done():
            return  # Reconnection already scheduled

        async def reconnect() -> None:
            while not self._shutdown:
                # Jitter spreads the reconnections of many installations
                # after a backend outage (not used for security).
                delay = self._reconnect_delay * random.uniform(  # noqa: S311
                    1 - WEBSOCKET_RECONNECT_JITTER, 1 + WEBSOCKET_RECONNECT_JITTER
                )
                _LOGGER.info(
                    "Attempting to reconnect to Sabiana WebSocket in %.0fs...",
                    delay,
                )
                await asyncio.sleep(delay)

                if self._shutdown:
                    break

                connected = await self._async_try_connect()
                if connected:
                    _LOGGER.info("Successfully reconnected to Sabiana WebSocket")
                    return

                # Exponential backoff: double the delay, cap at max
                self._increase_backoff()
                _LOGGER.warning(
                    "Reconnection failed, next attempt in %ds",
                    self._reconnect_delay,
                )

        self._reconnect_task = asyncio.create_task(reconnect())

    def _trigger_refresh_callbacks(self) -> None:
        """Ask for a re-read of the device list (after a reconnection)."""
        for callback in self._refresh_callbacks:
            try:
                callback()
            except Exception:
                _LOGGER.exception("Error in refresh callback after reconnection")

    async def async_disconnect(self) -> None:
        """Disconnect from the WebSocket server."""
        self._shutdown = True

        if self._reconnect_task is not None:
            self._reconnect_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._reconnect_task
            self._reconnect_task = None

        if self._sio is not None and self._connected:
            try:
                await self._sio.disconnect()
                _LOGGER.info("Disconnected from Sabiana WebSocket")
            except Exception:
                _LOGGER.exception("Error disconnecting from WebSocket")
            finally:
                self._connected = False
                self._sio = None
        await self._async_close_http_session()
