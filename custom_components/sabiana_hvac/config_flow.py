"""
Configuration flow for Sabiana HVAC integration.

This module handles the setup and configuration of the Sabiana HVAC
integration through Home Assistant's config flow system.
"""

import logging
from datetime import datetime, timedelta
from typing import Any

import httpx
import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.helpers.httpx_client import get_async_client

from . import api
from .const import (
    CONF_LONG_JWT,
    CONF_SHORT_JWT,
    DOMAIN,
    ERROR_API_ERROR,
    ERROR_CANNOT_CONNECT,
    ERROR_INVALID_AUTH,
    ERROR_TIMEOUT,
    ERROR_UNKNOWN,
)

_LOGGER = logging.getLogger(__name__)


class SabianaHvacConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle configuration flow for Sabiana HVAC integration."""

    VERSION = 1

    def __init__(self, datetime: datetime) -> None:
        """
        Initialize the config flow.

        Args:
            datetime: The datetime module to use for time operations.

        """
        super().__init__()
        self._datetime = datetime

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """
        Handle the initial step of the config flow.

        Args:
            user_input: User input data containing email and password.

        Returns:
            ConfigFlowResult indicating the next step or errors.

        """
        errors: dict[str, str] = {}

        if user_input is not None:
            email = user_input[CONF_EMAIL]
            password = user_input[CONF_PASSWORD]

            try:
                session = get_async_client(self.hass)
                auth_result = await api.async_authenticate(session, email, password)
                short_jwt, long_jwt = auth_result
                _LOGGER.info("Successfully authenticated with Sabiana API")

            except api.SabianaApiAuthError as err:
                _LOGGER.warning(
                    "Authentication failed (%s): %s", ERROR_INVALID_AUTH, err
                )
                errors["base"] = ERROR_INVALID_AUTH
            except httpx.ConnectError:
                _LOGGER.exception("Connection error (%s)", ERROR_CANNOT_CONNECT)
                errors["base"] = ERROR_CANNOT_CONNECT
            except httpx.TimeoutException:
                _LOGGER.exception("Timeout error (%s)", ERROR_TIMEOUT)
                errors["base"] = ERROR_TIMEOUT
            except api.SabianaApiClientError:
                _LOGGER.exception("API client error (%s)", ERROR_API_ERROR)
                errors["base"] = ERROR_API_ERROR
            except Exception:
                _LOGGER.exception(
                    "Unexpected error during authentication (%s)",
                    ERROR_UNKNOWN,
                )
                errors["base"] = ERROR_UNKNOWN

            else:
                await self.async_set_unique_id(email.lower())
                self._abort_if_unique_id_configured()

                return self.async_create_entry(
                    title=f"Sabiana HVAC ({email})",
                    data={
                        CONF_EMAIL: email,
                        CONF_PASSWORD: password,
                        CONF_SHORT_JWT: short_jwt,
                        CONF_LONG_JWT: long_jwt,
                    },
                )

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_EMAIL): str,
                    vol.Required(CONF_PASSWORD): str,
                }
            ),
            errors=errors,
        )
