import base64
import json
from datetime import UTC, datetime

import pytest

from custom_components.sabiana_hvac.models import JWT


def create_test_jwt(exp_timestamp: int | None = None) -> str:
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
    return create_test_jwt()


@pytest.fixture
def sample_long_jwt_token() -> str:
    exp_timestamp = int(datetime.now(UTC).timestamp()) + 86400 * 30
    return create_test_jwt(exp_timestamp)


@pytest.fixture
def sample_authenticate_response(sample_short_jwt_token, sample_long_jwt_token) -> dict:
    return {
        "status": 0,
        "body": {
            "user": {
                "shortJwt": sample_short_jwt_token,
                "longJwt": sample_long_jwt_token,
            }
        },
    }


@pytest.fixture
def sample_devices_response() -> dict:
    return {
        "status": 0,
        "body": {
            "devices": [
                {"idDevice": "device1", "deviceName": "Device 1"},
                {"idDevice": "device2", "deviceName": "Device 2"},
            ]
        },
    }


@pytest.fixture
def sample_renew_jwt_response(sample_short_jwt_token) -> dict:
    return {
        "status": 0,
        "body": {
            "newToken": sample_short_jwt_token,
        },
    }


@pytest.fixture
def sample_send_command_response() -> dict:
    return {
        "status": 0,
        "body": {
            "result": True,
        },
    }
