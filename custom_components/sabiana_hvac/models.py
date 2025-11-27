"""Data models for Sabiana HVAC integration."""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class JWT:
    """Represents a JWT token with its expiration timestamp."""

    token: str
    expire_at: datetime


@dataclass(slots=True)
class SabianaDeviceState:
    """Represents the current operating state reported by the Sabiana API."""

    hvac_mode: int | str | None
    target_temperature: float | int | None
    current_temperature: float | int | None
    fan_mode: int | str | None
    swing_mode: int | str | None
    preset_mode: int | str | None
    power_on: int | bool | None
    controller_model: str | None  # Controller model code (e.g., "5004" for Carisma Fly)
    raw_state: dict