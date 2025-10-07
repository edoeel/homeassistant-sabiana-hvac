import logging
from typing import Any

import httpx
import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.helpers.httpx_client import get_async_client

from . import api
from .const import (
    CONF_TOKEN,
    DOMAIN,
    ERROR_API_ERROR,
    ERROR_CANNOT_CONNECT,
    ERROR_INVALID_AUTH,
    ERROR_TIMEOUT,
    ERROR_UNKNOWN,
)

_LOGGER = logging.getLogger(__name__)


class SabianaHvacConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            email = user_input[CONF_EMAIL]
            password = user_input[CONF_PASSWORD]

            try:
                session = get_async_client(self.hass)
                token = await api.async_authenticate(session, email, password)
                _LOGGER.info("Successfully authenticated with Sabiana API")

            except api.SabianaApiAuthError as err:
                _LOGGER.warning(
                    "Authentication failed (%s): %s", ERROR_INVALID_AUTH, err
                )
                errors["base"] = ERROR_INVALID_AUTH
            except httpx.ConnectError as err:
                _LOGGER.error("Connection error (%s): %s", ERROR_CANNOT_CONNECT, err)
                errors["base"] = ERROR_CANNOT_CONNECT
            except httpx.TimeoutException as err:
                _LOGGER.error("Timeout error (%s): %s", ERROR_TIMEOUT, err)
                errors["base"] = ERROR_TIMEOUT
            except api.SabianaApiClientError as err:
                _LOGGER.error("API client error (%s): %s", ERROR_API_ERROR, err)
                errors["base"] = ERROR_API_ERROR
            except Exception as err:
                _LOGGER.exception(
                    "Unexpected error during authentication (%s): %s",
                    ERROR_UNKNOWN,
                    err,
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
                        CONF_TOKEN: token,
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
