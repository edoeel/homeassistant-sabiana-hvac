"""Pytest configuration and fixtures for Sabiana HVAC tests."""

import base64
import json
from datetime import UTC, datetime

import pytest


def create_test_jwt(exp_timestamp: int | None = None) -> str:
    """Create a test JWT token with optional expiration timestamp.

    Args:
        exp_timestamp: Optional expiration timestamp. If None, defaults to
            1 hour from now.

    Returns:
        A JWT token string with header, payload, and signature.

    """
    if exp_timestamp is None:
        exp_timestamp = int(datetime.now(UTC).timestamp()) + 3600

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"exp": exp_timestamp, "sub": "test_user"}

    header_encoded = (
        base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    )
    payload_encoded = (
        base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    )

    return f"{header_encoded}.{payload_encoded}.signature"


@pytest.fixture
def sample_short_jwt_token() -> str:
    """Fixture providing a short-lived JWT token (1 hour expiration)."""
    return create_test_jwt()


@pytest.fixture
def sample_long_jwt_token() -> str:
    """Fixture providing a long-lived JWT token (30 days expiration)."""
    exp_timestamp = int(datetime.now(UTC).timestamp()) + 86400 * 30
    return create_test_jwt(exp_timestamp)


@pytest.fixture
def sample_authenticate_response(
    sample_short_jwt_token: str,
    sample_long_jwt_token: str,
) -> dict:
    """Fixture providing a sample authenticate API response.

    Args:
        sample_short_jwt_token: Short-lived JWT token fixture.
        sample_long_jwt_token: Long-lived JWT token fixture.

    Returns:
        A dictionary representing an authenticate API response.

    """
    return {
        "status": 0,
        "body": {
            "user": {
                "shortJwt": sample_short_jwt_token,
                "longJwt": sample_long_jwt_token,
            },
        },
    }


@pytest.fixture
def sample_devices_response() -> dict:
    """Fixture providing a sample devices API response.

    Returns:
        A dictionary representing a devices API response with sample devices.

    """
    return {
        "status": 0,
        "body": {
            "devices": [
                {"idDevice": "device1", "deviceName": "Device 1"},
                {"idDevice": "device2", "deviceName": "Device 2"},
            ],
        },
    }


@pytest.fixture
def sample_renew_jwt_response(sample_short_jwt_token: str) -> dict:
    """Fixture providing a sample JWT renewal API response.

    Args:
        sample_short_jwt_token: Short-lived JWT token fixture.

    Returns:
        A dictionary representing a JWT renewal API response.

    """
    return {
        "status": 0,
        "body": {
            "newToken": sample_short_jwt_token,
        },
    }


@pytest.fixture
def sample_send_command_response() -> dict:
    """Fixture providing a sample send command API response.

    Returns:
        A dictionary representing a send command API response.

    """
    return {
        "status": 0,
        "body": {
            "result": True,
        },
    }
