"""Tests for the Sabiana WebSocket manager."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import socketio.exceptions

from custom_components.sabiana_hvac.models import SabianaDeviceState
from custom_components.sabiana_hvac.websocket import (
    SabianaWebSocketManager,
    WebSocketConnectionEvent,
    WebSocketDeviceUpdate,
)

if TYPE_CHECKING:
    from collections.abc import Callable


@pytest.fixture
def mock_hass() -> MagicMock:
    """Create a mock Home Assistant instance."""
    hass = MagicMock()
    hass.async_create_task = MagicMock(
        side_effect=lambda coro: asyncio.create_task(coro)
    )
    return hass


@pytest.fixture
def get_token() -> MagicMock:
    """Create a mock token getter."""
    return MagicMock(return_value="test_jwt_token")


@pytest.fixture
def websocket_manager(
    mock_hass: MagicMock, get_token: Callable[[], str]
) -> SabianaWebSocketManager:
    """Create a WebSocket manager instance."""
    return SabianaWebSocketManager(mock_hass, get_token)


class TestWebSocketManager:
    """Tests for SabianaWebSocketManager."""

    def test_init(self, websocket_manager: SabianaWebSocketManager) -> None:
        """Test WebSocket manager initialization."""
        assert websocket_manager._connected is False
        assert websocket_manager._sio is None
        assert websocket_manager._shutdown is False

    def test_connected_property(
        self, websocket_manager: SabianaWebSocketManager
    ) -> None:
        """Test connected property returns connection state."""
        assert websocket_manager.connected is False
        websocket_manager._connected = True
        assert websocket_manager.connected is True

    def test_register_device_update_callback(
        self, websocket_manager: SabianaWebSocketManager
    ) -> None:
        """Test registering a device update callback."""
        callback = MagicMock()
        unregister = websocket_manager.register_device_update_callback(callback)

        assert callback in websocket_manager._device_update_callbacks

        # Test unregister
        unregister()
        assert callback not in websocket_manager._device_update_callbacks

    def test_register_connection_event_callback(
        self, websocket_manager: SabianaWebSocketManager
    ) -> None:
        """Test registering a connection event callback."""
        callback = MagicMock()
        unregister = websocket_manager.register_connection_event_callback(callback)

        assert callback in websocket_manager._connection_event_callbacks

        # Test unregister
        unregister()
        assert callback not in websocket_manager._connection_event_callbacks

    def test_register_refresh_callback(
        self, websocket_manager: SabianaWebSocketManager
    ) -> None:
        """Test registering a refresh callback."""
        callback = MagicMock()
        unregister = websocket_manager.register_refresh_callback(callback)

        assert callback in websocket_manager._refresh_callbacks

        # Test unregister
        unregister()
        assert callback not in websocket_manager._refresh_callbacks

    @pytest.mark.asyncio
    async def test_connect_no_token(self, mock_hass: MagicMock) -> None:
        """Test connection fails when no token is available."""
        get_token = MagicMock(return_value="")
        manager = SabianaWebSocketManager(mock_hass, get_token)

        result = await manager.async_connect()

        assert result is False
        assert manager.connected is False

    @pytest.mark.asyncio
    async def test_connect_success(
        self, websocket_manager: SabianaWebSocketManager
    ) -> None:
        """Test successful WebSocket connection."""
        mock_sio = MagicMock()
        mock_sio.connect = AsyncMock()
        # The .on() method is a decorator, must return the decorated function unchanged
        mock_sio.on = MagicMock(side_effect=lambda _event: lambda f: f)

        with patch(
            "custom_components.sabiana_hvac.websocket.socketio.AsyncClient"
        ) as mock_client:
            mock_client.return_value = mock_sio

            result = await websocket_manager.async_connect()

            assert result is True
            assert websocket_manager.connected is True
            mock_sio.connect.assert_called_once()

    @pytest.mark.asyncio
    async def test_connect_failure(
        self, websocket_manager: SabianaWebSocketManager
    ) -> None:
        """Test WebSocket connection failure."""
        mock_sio = MagicMock()
        mock_sio.connect = AsyncMock(
            side_effect=socketio.exceptions.ConnectionError("Connection refused")
        )
        # The .on() method is a decorator, must return the decorated function unchanged
        mock_sio.on = MagicMock(side_effect=lambda _event: lambda f: f)

        with patch(
            "custom_components.sabiana_hvac.websocket.socketio.AsyncClient"
        ) as mock_client:
            mock_client.return_value = mock_sio

            result = await websocket_manager.async_connect()

            assert result is False
            assert websocket_manager.connected is False

    @pytest.mark.asyncio
    async def test_disconnect(self, websocket_manager: SabianaWebSocketManager) -> None:
        """Test WebSocket disconnection."""
        mock_sio = AsyncMock()
        mock_sio.disconnect = AsyncMock()

        websocket_manager._sio = mock_sio
        websocket_manager._connected = True

        await websocket_manager.async_disconnect()

        assert websocket_manager._shutdown is True
        mock_sio.disconnect.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_data_event(
        self, websocket_manager: SabianaWebSocketManager
    ) -> None:
        """Test handling of data events."""
        callback = MagicMock()
        websocket_manager.register_device_update_callback(callback)

        # Simulate a data event
        # This is a minimal valid hex string that will decode to a state
        test_data = {
            "device": "test_device_id",
            "data": "00500001140100010010D8000E00D2FFFF0000000000000000",
        }

        await websocket_manager._handle_data_event(test_data)

        assert callback.called
        call_args = callback.call_args[0][0]
        assert isinstance(call_args, WebSocketDeviceUpdate)
        assert call_args.device_id == "test_device_id"

    @pytest.mark.asyncio
    async def test_handle_data_event_invalid(
        self, websocket_manager: SabianaWebSocketManager
    ) -> None:
        """Test handling of invalid data events."""
        callback = MagicMock()
        websocket_manager.register_device_update_callback(callback)

        # Missing device or data
        await websocket_manager._handle_data_event({"device": "test"})
        await websocket_manager._handle_data_event({"data": "test"})
        await websocket_manager._handle_data_event({})

        # Callback should not be called for invalid events
        assert not callback.called

    @pytest.mark.asyncio
    async def test_handle_connection_event_connect(
        self, websocket_manager: SabianaWebSocketManager
    ) -> None:
        """Test handling of connection events - connect."""
        callback = MagicMock()
        websocket_manager.register_connection_event_callback(callback)

        test_data = {
            "device": "test_device_id",
            "data": "CONNECT",
        }

        await websocket_manager._handle_connection_event(test_data)

        assert callback.called
        call_args = callback.call_args[0][0]
        assert isinstance(call_args, WebSocketConnectionEvent)
        assert call_args.device_id == "test_device_id"
        assert call_args.connected is True

    @pytest.mark.asyncio
    async def test_handle_connection_event_disconnect(
        self, websocket_manager: SabianaWebSocketManager
    ) -> None:
        """Test handling of connection events - disconnect."""
        callback = MagicMock()
        websocket_manager.register_connection_event_callback(callback)

        test_data = {
            "device": "test_device_id",
            "data": "DISCONNECT",
        }

        await websocket_manager._handle_connection_event(test_data)

        assert callback.called
        call_args = callback.call_args[0][0]
        assert call_args.connected is False

    @pytest.mark.asyncio
    async def test_async_refresh(
        self, websocket_manager: SabianaWebSocketManager
    ) -> None:
        """Test sending refresh request."""
        mock_sio = AsyncMock()
        mock_sio.emit = AsyncMock()

        websocket_manager._sio = mock_sio
        websocket_manager._connected = True

        await websocket_manager.async_refresh()

        mock_sio.emit.assert_called_once_with("refresh", {})

    @pytest.mark.asyncio
    async def test_async_refresh_not_connected(
        self, websocket_manager: SabianaWebSocketManager
    ) -> None:
        """Test refresh does nothing when not connected."""
        websocket_manager._sio = None
        websocket_manager._connected = False

        # Should not raise any errors
        await websocket_manager.async_refresh()


class TestWebSocketDeviceUpdate:
    """Tests for WebSocketDeviceUpdate dataclass."""

    def test_create(self) -> None:
        """Test creating a WebSocketDeviceUpdate."""
        state = SabianaDeviceState(
            hvac_mode="heat",
            target_temperature=22.0,
            current_temperature=21.0,
            fan_mode="auto",
            swing_mode="off",
            preset_mode="none",
            power_on=True,
            controller_model="5020",
            raw_state={},
        )

        update = WebSocketDeviceUpdate(device_id="test123", state=state)

        assert update.device_id == "test123"
        assert update.state == state


class TestWebSocketConnectionEvent:
    """Tests for WebSocketConnectionEvent dataclass."""

    def test_create_connected(self) -> None:
        """Test creating a connection event for connect."""
        event = WebSocketConnectionEvent(device_id="test123", connected=True)

        assert event.device_id == "test123"
        assert event.connected is True

    def test_create_disconnected(self) -> None:
        """Test creating a connection event for disconnect."""
        event = WebSocketConnectionEvent(device_id="test123", connected=False)

        assert event.device_id == "test123"
        assert event.connected is False
