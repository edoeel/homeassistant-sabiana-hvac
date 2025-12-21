"""WebSocket manager for Sabiana HVAC real-time updates.

This module provides a Socket.IO client that connects to the Sabiana
cloud WebSocket server for receiving real-time device state updates.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import socketio

from .api import decode_last_data
from .const import WEBSOCKET_RECONNECT_DELAY, WEBSOCKET_URL

if TYPE_CHECKING:
    from collections.abc import Callable

    from homeassistant.core import HomeAssistant

    from .models import SabianaDeviceState

_LOGGER = logging.getLogger(__name__)


@dataclass
class WebSocketDeviceUpdate:
    """Represents a device state update received via WebSocket."""

    device_id: str
    state: SabianaDeviceState


@dataclass
class WebSocketConnectionEvent:
    """Represents a device connection event received via WebSocket."""

    device_id: str
    connected: bool


class SabianaWebSocketManager:
    """Manager for Sabiana Socket.IO WebSocket connection.

    This class handles the Socket.IO connection to the Sabiana cloud server,
    authenticates using JWT tokens, and dispatches device updates to registered
    callbacks.

    The Socket.IO events handled are:
    - data: Device state updates with lastData hex string
    - connEvents: Device connection/disconnection events
    - status: Device status updates (firmware version, WiFi RSSI)
    - appMsg: Application messages (e.g., refresh requests)
    """

    def __init__(
        self,
        hass: HomeAssistant,
        get_token: Callable[[], str],
    ) -> None:
        """Initialize the WebSocket manager.

        Args:
            hass: Home Assistant instance.
            get_token: Callback function to get the current JWT token.

        """
        self._hass = hass
        self._get_token = get_token
        self._sio: socketio.AsyncClient | None = None
        self._connected = False
        self._reconnect_task: asyncio.Task[None] | None = None
        self._shutdown = False

        # Callbacks for different event types
        self._device_update_callbacks: list[
            Callable[[WebSocketDeviceUpdate], None]
        ] = []
        self._connection_event_callbacks: list[
            Callable[[WebSocketConnectionEvent], None]
        ] = []
        self._refresh_callbacks: list[Callable[[], None]] = []

    @property
    def connected(self) -> bool:
        """Return True if WebSocket is connected."""
        return self._connected

    def register_device_update_callback(
        self,
        callback: Callable[[WebSocketDeviceUpdate], None],
    ) -> Callable[[], None]:
        """Register a callback for device state updates.

        Args:
            callback: Function to call when a device update is received.

        Returns:
            A function to unregister the callback.

        """
        self._device_update_callbacks.append(callback)

        def unregister() -> None:
            if callback in self._device_update_callbacks:
                self._device_update_callbacks.remove(callback)

        return unregister

    def register_connection_event_callback(
        self,
        callback: Callable[[WebSocketConnectionEvent], None],
    ) -> Callable[[], None]:
        """Register a callback for device connection events.

        Args:
            callback: Function to call when a connection event is received.

        Returns:
            A function to unregister the callback.

        """
        self._connection_event_callbacks.append(callback)

        def unregister() -> None:
            if callback in self._connection_event_callbacks:
                self._connection_event_callbacks.remove(callback)

        return unregister

    def register_refresh_callback(
        self,
        callback: Callable[[], None],
    ) -> Callable[[], None]:
        """Register a callback for refresh requests.

        Args:
            callback: Function to call when a refresh is requested.

        Returns:
            A function to unregister the callback.

        """
        self._refresh_callbacks.append(callback)

        def unregister() -> None:
            if callback in self._refresh_callbacks:
                self._refresh_callbacks.remove(callback)

        return unregister

    async def async_connect(self) -> bool:
        """Connect to the Sabiana WebSocket server.

        Returns:
            True if connection was successful, False otherwise.

        """
        if self._sio is not None and self._connected:
            _LOGGER.debug("Already connected to Sabiana WebSocket")
            return True

        try:
            token = self._get_token()
            if not token:
                _LOGGER.error("Cannot connect to WebSocket: no JWT token available")
                return False

            self._sio = socketio.AsyncClient(
                reconnection=False,  # We handle reconnection ourselves
                logger=False,
                engineio_logger=False,
            )

            # Register event handlers
            self._register_event_handlers()

            _LOGGER.info("Connecting to Sabiana WebSocket at %s", WEBSOCKET_URL)

            await self._sio.connect(
                WEBSOCKET_URL,
                auth={"token": token},
                transports=["websocket", "polling"],
            )

            self._connected = True
            _LOGGER.info("Successfully connected to Sabiana WebSocket")

        except socketio.exceptions.ConnectionError as err:
            _LOGGER.warning("Failed to connect to Sabiana WebSocket: %s", err)
            self._connected = False
        except Exception:
            _LOGGER.exception("Unexpected error connecting to Sabiana WebSocket")
            self._connected = False

        return self._connected

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
        async def disconnect() -> None:
            """Handle disconnection."""
            _LOGGER.warning("Sabiana WebSocket disconnected")
            self._connected = False
            # Schedule reconnection
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
            _LOGGER.debug("Received status update: %s", data)
            # Status updates contain firmware and WiFi info, not state changes
            # We could extend this later if needed

        @self._sio.on("appMsg")
        async def on_app_msg(data: dict[str, Any]) -> None:
            """Handle application messages.

            Event format: { msg: "refresh" }
            """
            if data and data.get("msg") == "refresh":
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

    async def _handle_data_event(self, data: dict[str, Any]) -> None:
        """Process a device data update event."""
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

        try:
            state = decode_last_data(hex_data)
            update = WebSocketDeviceUpdate(device_id=device_id, state=state)

            for callback in self._device_update_callbacks:
                try:
                    callback(update)
                except Exception:
                    _LOGGER.exception("Error in device update callback")

        except Exception:
            _LOGGER.exception("Error decoding device data: %s", hex_data)

    async def _handle_connection_event(self, data: dict[str, Any]) -> None:
        """Process a device connection event."""
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
        """Schedule a reconnection attempt."""
        if self._reconnect_task is not None and not self._reconnect_task.done():
            return  # Reconnection already scheduled

        async def reconnect() -> None:
            await asyncio.sleep(WEBSOCKET_RECONNECT_DELAY)
            if not self._shutdown:
                _LOGGER.info("Attempting to reconnect to Sabiana WebSocket...")
                await self.async_connect()

        self._reconnect_task = asyncio.create_task(reconnect())

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

    async def async_refresh(self) -> None:
        """Send a refresh request to the server.

        This emits a 'refresh' event to request updated device list.
        """
        if self._sio is not None and self._connected:
            try:
                await self._sio.emit("refresh", {})
                _LOGGER.debug("Sent refresh request to Sabiana WebSocket")
            except Exception:
                _LOGGER.exception("Error sending refresh request")
