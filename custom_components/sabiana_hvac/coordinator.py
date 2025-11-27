"""Coordinator for Sabiana HVAC integration."""

from __future__ import annotations

import logging
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
    DEFAULT_POLL_INTERVAL,
    DOMAIN,
)
from .models import JWT, SabianaDeviceState

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)


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
        """Check token expiration and refresh if needed."""
        now = datetime.now(UTC)

        if now >= self.long_jwt.expire_at:
            _LOGGER.warning("Long JWT expired, performing full re-authentication")
            short_jwt, long_jwt = await self._async_reauth()
            self._update_tokens(short_jwt, long_jwt)
            return short_jwt.token

        if now >= self.short_jwt.expire_at:
            _LOGGER.debug("Short JWT expired, refreshing using long JWT")
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
        _LOGGER.debug("Config entry data: %s", self.config_entry.data)
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


class SabianaDeviceCoordinator(
    DataUpdateCoordinator[dict[str, SabianaDeviceState]]
):
    """Coordinator that polls Sabiana device states."""

    def __init__(
        self,
        hass: HomeAssistant,
        session: httpx.AsyncClient,
        token_coordinator: SabianaTokenCoordinator,
        device_ids: list[str],
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_devices",
            update_interval=timedelta(seconds=DEFAULT_POLL_INTERVAL),
        )
        self._session = session
        self._token_coordinator = token_coordinator
        self._device_ids = device_ids
        self.data = {}

    async def _async_update_data(self) -> dict[str, SabianaDeviceState]:
        if not self._device_ids:
            _LOGGER.debug("No Sabiana devices registered for polling")
            return {}

        await self._token_coordinator.async_request_refresh()
        short_jwt = self._token_coordinator.data

        try:
            # Get devices which includes lastData with current state
            response = await self._session.get(
                f"{api.BASE_URL}/devices/getDeviceForUserV2",
                headers=api.create_headers(short_jwt),
            )
            data = api.validate_response(response)
            states = api.extract_device_states_from_devices(data)
            
            _LOGGER.debug("Polled status for %d devices", len(states))
        except api.SabianaApiAuthError as err:
            raise UpdateFailed(f"Authentication error while polling devices: {err}") from err
        except api.SabianaApiClientError as err:
            raise UpdateFailed(f"API error while polling devices: {err}") from err
        except httpx.RequestError as err:
            raise UpdateFailed(f"Connection error while polling devices: {err}") from err

        # Filter to only return states for our tracked devices
        filtered_states = {
            device_id: state 
            for device_id, state in states.items() 
            if device_id in self._device_ids
        }

        missing = set(self._device_ids) - set(filtered_states)
        if missing:
            _LOGGER.debug("Did not receive state for devices: %s", missing)

        return filtered_states
