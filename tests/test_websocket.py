# Copyright (c) 2026 Edoardo Mistretta

"""Tests for the Sabiana Socket.IO manager."""

import logging
import time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
import socketio

from custom_components.sabiana_hvac import websocket
from custom_components.sabiana_hvac.const import WEBSOCKET_URL
from custom_components.sabiana_hvac.models import JWT
from custom_components.sabiana_hvac.websocket import (
    SabianaWebSocketManager,
    WebSocketConnectionEvent,
    WebSocketDeviceUpdate,
    WebSocketStatusEvent,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

RSSI = -61
STABLE_FOR = 120  # seconds, longer than WEBSOCKET_STABLE_CONNECTION


@contextmanager
def no_jitter() -> Iterator[None]:
    """Make the reconnection delays deterministic."""
    with patch.object(websocket.random, "uniform", return_value=1.0):
        yield


class FakeAsyncClient:
    """Stand-in for socketio.AsyncClient that records handlers and calls."""

    instances: list[FakeAsyncClient] = []  # noqa: RUF012
    connect_side_effects: list[Exception | None] = []  # noqa: RUF012

    def __init__(self, **kwargs: object) -> None:
        """Record the constructor options."""
        self.options = kwargs
        self.handlers: dict[str, Callable[..., Any]] = {}
        self.connect = AsyncMock(side_effect=self._connect)
        self.disconnect = AsyncMock()
        FakeAsyncClient.instances.append(self)

    async def _connect(self, *_args: object, **_kwargs: object) -> None:
        if FakeAsyncClient.connect_side_effects:
            error = FakeAsyncClient.connect_side_effects.pop(0)
            if error is not None:
                raise error

    def event(self, handler: Callable[..., Any]) -> Callable[..., Any]:
        """Register a handler under its function name."""
        self.handlers[handler.__name__] = handler
        return handler

    def on(self, name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Register a handler for a named event."""

        def decorator(handler: Callable[..., Any]) -> Callable[..., Any]:
            self.handlers[name] = handler
            return handler

        return decorator

    async def emit_event(self, name: str, *args: object) -> None:
        """Simulate an event coming from the server."""
        await self.handlers[name](*args)


@pytest.fixture(autouse=True)
def fake_socketio() -> Iterator[type[FakeAsyncClient]]:
    """Replace the Socket.IO client and its aiohttp session."""
    FakeAsyncClient.instances = []
    FakeAsyncClient.connect_side_effects = []
    session = MagicMock()
    session.close = AsyncMock()
    with (
        patch.object(websocket.socketio, "AsyncClient", FakeAsyncClient),
        patch.object(websocket.aiohttp, "ClientSession", return_value=session),
        patch.object(websocket.aiohttp, "TCPConnector"),
        patch.object(websocket.aiohttp, "ThreadedResolver"),
    ):
        yield FakeAsyncClient


@pytest.fixture
def jwt() -> JWT:
    """Return a short JWT valid for 10 minutes."""
    return JWT(token="short-token", expire_at=datetime.now(UTC) + timedelta(minutes=10))  # noqa: S106


@pytest.fixture
def manager(jwt: JWT) -> SabianaWebSocketManager:
    """Create a manager with a token refresh mock."""
    return SabianaWebSocketManager(
        Mock(), lambda: jwt, refresh_token=AsyncMock(return_value=None)
    )


def _client() -> FakeAsyncClient:
    return FakeAsyncClient.instances[-1]


class TestConnect:
    """Connection and handshake."""

    @pytest.mark.asyncio
    async def test_handshake_uses_short_jwt(
        self, manager: SabianaWebSocketManager
    ) -> None:
        """The handshake carries auth.token, as in the app."""
        assert await manager.async_connect() is True
        assert manager.connected is True
        client = _client()
        client.connect.assert_awaited_once()
        assert client.connect.await_args.args == (WEBSOCKET_URL,)
        assert client.connect.await_args.kwargs["auth"] == {"token": "short-token"}
        assert client.options["reconnection"] is False

    @pytest.mark.asyncio
    async def test_refreshes_token_before_connecting(
        self, manager: SabianaWebSocketManager
    ) -> None:
        """The token is renewed (if needed) before each handshake."""
        await manager.async_connect()
        manager._refresh_token.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_first_connect_does_not_reread(
        self, manager: SabianaWebSocketManager
    ) -> None:
        """The list was just read at setup: the first connect only notifies."""
        refresh, status = Mock(), Mock()
        manager.register_refresh_callback(refresh)
        manager.register_connection_status_callback(status)
        await manager.async_connect()
        status.assert_called_once_with(connected=True)
        refresh.assert_not_called()

    @pytest.mark.asyncio
    async def test_failed_first_connect_schedules_reconnection(
        self, manager: SabianaWebSocketManager
    ) -> None:
        """A failed connection at setup is retried in the background."""
        FakeAsyncClient.connect_side_effects = [
            socketio.exceptions.ConnectionError("refused"),
        ]
        with patch.object(websocket.asyncio, "sleep", AsyncMock()):
            assert await manager.async_connect() is False
            assert manager._reconnect_task is not None
            await manager._reconnect_task
        assert manager.connected is True
        assert len(FakeAsyncClient.instances) == 2  # noqa: PLR2004


class TestReconnect:
    """Disconnections and reconnections."""

    @pytest.mark.asyncio
    async def test_reconnection_rereads_device_list(
        self, manager: SabianaWebSocketManager
    ) -> None:
        """After a drop, the new connection re-reads the list (app behavior)."""
        refresh, status = Mock(), Mock()
        manager.register_refresh_callback(refresh)
        manager.register_connection_status_callback(status)
        await manager.async_connect()

        with patch.object(websocket.asyncio, "sleep", AsyncMock()):
            await _client().emit_event("disconnect", "transport close")
            assert manager.connected is False
            status.assert_called_with(connected=False)
            await manager._reconnect_task

        assert manager.connected is True
        status.assert_called_with(connected=True)
        refresh.assert_called_once()

    @pytest.mark.asyncio
    async def test_failed_attempts_back_off_without_rest_reads(
        self, manager: SabianaWebSocketManager
    ) -> None:
        """After a stable connection: 5, 10, 20 s, and no REST reads meanwhile."""
        refresh = Mock()
        manager.register_refresh_callback(refresh)
        await manager.async_connect()
        manager._connected_at = time.monotonic() - STABLE_FOR
        FakeAsyncClient.connect_side_effects = [OSError("down"), OSError("down"), None]
        sleep = AsyncMock()
        with no_jitter(), patch.object(websocket.asyncio, "sleep", sleep):
            await _client().emit_event("disconnect", "transport error")
            await manager._reconnect_task

        assert [c.args[0] for c in sleep.await_args_list] == [5, 10, 20]
        # only the re-read after the successful reconnection, as in the app
        refresh.assert_called_once()
        # not reset yet: the new connection has not proved stable
        assert manager._reconnect_delay == 20  # noqa: PLR2004

    @pytest.mark.asyncio
    async def test_delay_is_capped_at_one_minute(
        self, manager: SabianaWebSocketManager
    ) -> None:
        """Long outages retry once a minute, never faster growing."""
        FakeAsyncClient.connect_side_effects = [OSError("down")] * 7 + [None]
        sleep = AsyncMock()
        with no_jitter(), patch.object(websocket.asyncio, "sleep", sleep):
            await manager.async_connect()
            await manager._reconnect_task
        assert [c.args[0] for c in sleep.await_args_list] == [
            5,
            10,
            20,
            40,
            60,
            60,
            60,
        ]

    @pytest.mark.asyncio
    async def test_short_lived_connections_keep_backing_off(
        self, manager: SabianaWebSocketManager
    ) -> None:
        """A server that accepts and drops at once is not hammered every 5 s."""
        await manager.async_connect()
        with patch.object(manager, "_schedule_reconnect"):
            await _client().emit_event("disconnect", "io server disconnect")
        assert manager._reconnect_delay == 10  # noqa: PLR2004

    @pytest.mark.asyncio
    async def test_stable_connection_resets_the_delay(
        self, manager: SabianaWebSocketManager
    ) -> None:
        """After a connection of at least a minute the delay starts again at 5 s."""
        manager._reconnect_delay = 60
        await manager.async_connect()
        manager._connected_at = time.monotonic() - STABLE_FOR
        with patch.object(manager, "_schedule_reconnect"):
            await _client().emit_event("disconnect", "transport close")
        assert manager._reconnect_delay == websocket.WEBSOCKET_RECONNECT_DELAY

    @pytest.mark.asyncio
    async def test_jitter(self, manager: SabianaWebSocketManager) -> None:
        """The delay is randomized by +/-50%, like the app's backoff."""
        FakeAsyncClient.connect_side_effects = [OSError("down"), None]
        sleep = AsyncMock()
        with (
            patch.object(websocket.random, "uniform", return_value=1.5) as uniform,
            patch.object(websocket.asyncio, "sleep", sleep),
        ):
            await manager.async_connect()
            await manager._reconnect_task
        uniform.assert_called_with(0.5, 1.5)
        assert sleep.await_args_list[0].args[0] == 7.5  # noqa: PLR2004

    @pytest.mark.asyncio
    async def test_no_reconnection_after_shutdown(
        self, manager: SabianaWebSocketManager
    ) -> None:
        """async_disconnect stops the channel for good."""
        await manager.async_connect()
        client = _client()
        await manager.async_disconnect()
        client.disconnect.assert_awaited_once()
        await client.emit_event("disconnect", "io client disconnect")
        assert manager._reconnect_task is None
        assert manager.connected is False

    @pytest.mark.asyncio
    async def test_disconnect_logs_reason_and_jwt_expiry(
        self, manager: SabianaWebSocketManager, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The reason and the handshake JWT expiry are logged (diagnostics)."""
        caplog.set_level(logging.INFO, logger=websocket.__name__)
        await manager.async_connect()
        with patch.object(manager, "_schedule_reconnect"):
            await _client().emit_event("disconnect", "io server disconnect")
        assert "reason: io server disconnect" in caplog.text
        assert "handshake JWT expires in" in caplog.text


class TestEvents:
    """Server events forwarded to the callbacks."""

    @pytest.mark.asyncio
    async def test_data_event(self, manager: SabianaWebSocketManager) -> None:
        """The raw frame is forwarded undecoded."""
        callback = Mock()
        manager.register_device_update_callback(callback)
        await manager.async_connect()
        await _client().emit_event("data", {"device": "swm-1", "data": "500d0000"})
        callback.assert_called_once_with(
            WebSocketDeviceUpdate(device_id="swm-1", data="500d0000")
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("payload", "connected"), [("CONNECT", True), ("DISCONNECT", False)]
    )
    async def test_conn_events(
        self,
        manager: SabianaWebSocketManager,
        payload: str,
        connected: bool,  # noqa: FBT001
    ) -> None:
        """Only "CONNECT" means connected."""
        callback = Mock()
        manager.register_connection_event_callback(callback)
        await manager.async_connect()
        await _client().emit_event("connEvents", {"device": "swm-1", "data": payload})
        callback.assert_called_once_with(
            WebSocketConnectionEvent(device_id="swm-1", connected=connected)
        )

    @pytest.mark.asyncio
    async def test_status_event(self, manager: SabianaWebSocketManager) -> None:
        """Firmware and RSSI are forwarded; bad types become None."""
        callback = Mock()
        manager.register_status_callback(callback)
        await manager.async_connect()
        client = _client()
        await client.emit_event(
            "status",
            {"device": "swm-1", "deviceStateFw": "1.30", "deviceWiFiRSSI": RSSI},
        )
        await client.emit_event(
            "status", {"device": "swm-1", "deviceStateFw": 1, "deviceWiFiRSSI": "x"}
        )
        assert callback.call_args_list[0].args[0] == WebSocketStatusEvent(
            device_id="swm-1", wifi_fw="1.30", wifi_rssi=RSSI
        )
        assert callback.call_args_list[1].args[0] == WebSocketStatusEvent(
            device_id="swm-1", wifi_fw=None, wifi_rssi=None
        )

    @pytest.mark.asyncio
    async def test_app_msg_refresh(self, manager: SabianaWebSocketManager) -> None:
        """An appMsg {msg: "refresh"} asks for a re-read; other messages do not."""
        refresh = Mock()
        manager.register_refresh_callback(refresh)
        await manager.async_connect()
        client = _client()
        await client.emit_event("appMsg", {"msg": "other"})
        await client.emit_event("appMsg", "refresh")
        refresh.assert_not_called()
        await client.emit_event("appMsg", {"msg": "refresh"})
        refresh.assert_called_once()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("event", ["data", "connEvents", "status"])
    @pytest.mark.parametrize("payload", [None, "text", ["list"], {"device": ""}])
    async def test_malformed_payloads_are_dropped(
        self, manager: SabianaWebSocketManager, event: str, payload: object
    ) -> None:
        """Payloads that are not well-formed objects reach no callback."""
        callback = Mock()
        manager.register_device_update_callback(callback)
        manager.register_connection_event_callback(callback)
        manager.register_status_callback(callback)
        await manager.async_connect()
        await _client().emit_event(event, payload)
        callback.assert_not_called()
