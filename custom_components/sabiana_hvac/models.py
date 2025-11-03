"""Data models for Sabiana HVAC integration."""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class JWT:
    """Represents a JWT token with its expiration timestamp."""

    token: str
    expire_at: datetime
