# Sabiana HVAC Integration - Technical Architecture

## Purpose and Scope

This document explains how the `sabiana_hvac` custom integration works internally, how it integrates with Home Assistant, and which architectural decisions shape its current behavior.

The integration provides cloud-based control of compatible Sabiana HVAC units by:

- authenticating against Sabiana cloud APIs,
- discovering available devices,
- exposing each device as a Home Assistant `climate` entity,
- translating Home Assistant climate state changes into Sabiana command payloads.

This integration is currently designed around command delivery and token lifecycle management, with optimistic state handling on the Home Assistant side.

---

## High-Level System Architecture

At runtime, the integration is composed of five core modules:

- `config_flow.py` - interactive setup from Home Assistant UI.
- `__init__.py` - config entry lifecycle orchestration and platform forwarding.
- `api.py` - HTTP client logic, authentication, token parsing, and request/response validation.
- `coordinator.py` - token refresh and re-authentication lifecycle.
- `climate.py` - entity model and command generation for each discovered HVAC device.

Supporting modules:

- `const.py` - constants, API base URL, error keys, mode mappings.
- `models.py` - lightweight `JWT` data model.

---

## Integration with Home Assistant

### Manifest and Registration

The integration is registered through `custom_components/sabiana_hvac/manifest.json`:

- `domain`: `sabiana_hvac`
- `config_flow`: `true`
- `iot_class`: `cloud_polling`
- dependencies: `httpx`, `voluptuous`, `httpx-retries`

Only the `climate` platform is exposed (`PLATFORMS = [Platform.CLIMATE]`).

### Config Entry Lifecycle

Home Assistant integration lifecycle is implemented in `__init__.py`:

1. **`async_setup_entry`**
   - validates required JWT data in `ConfigEntry`,
   - creates a reusable HTTP session with retry support,
   - instantiates `SabianaTokenCoordinator`,
   - runs first coordinator refresh,
   - fetches devices from Sabiana API,
   - stores runtime objects in `hass.data[DOMAIN][entry_id]`,
   - forwards setup to the `climate` platform.

2. **`async_unload_entry`**
   - unloads climate platform entities,
   - removes cached runtime objects from `hass.data`.

The runtime data store for each entry contains:

- `session` (`httpx.AsyncClient`)
- `coordinator` (`SabianaTokenCoordinator`)
- `devices` (list of discovered Sabiana devices)

---

## Configuration Flow (UI Setup)

The user onboarding flow in `config_flow.py` follows Home Assistant's standard `ConfigFlow` model:

1. Prompt user for `email` and `password`.
2. Call `api.async_authenticate(...)`.
3. On success:
   - set unique ID to lowercase email (`async_set_unique_id(email.lower())`),
   - prevent duplicate setup for same account,
   - persist credentials and JWTs in the config entry.
4. On failure:
   - map connection/auth/API errors to localized HA form error keys.

### Data Persisted in ConfigEntry

The following fields are stored:

- account credentials:
  - `email`
  - `password`
- token data:
  - `short_jwt`
  - `short_jwt_expire_at` (unix timestamp)
  - `long_jwt`
  - `long_jwt_expire_at` (unix timestamp)

This allows startup without immediate re-login while enabling long-term automatic token maintenance.

---

## API Layer Design

The `api.py` module centralizes all communication with Sabiana cloud endpoints and enforces strict response validation.

### Endpoints Used

- `POST /users/newLogin` - authenticate with email/password and obtain short/long JWTs.
- `GET /devices/getDeviceForUserV2` - retrieve user devices.
- `POST /renewJwt` - renew short JWT using long JWT.
- `POST /devices/cmd` - send command payload to a specific device.

### HTTP Client and Retry

`create_session_client(...)` creates an HA-managed `httpx.AsyncClient` and applies `RetryTransport`:

- total retries: 3
- backoff factor: 0.5
- timeout: 5.0 seconds

This improves resilience for temporary cloud/network failures.

### Error Model

Custom exception hierarchy:

- `SabianaApiClientError` (base)
- `SabianaApiAuthError` (authentication-specific)

Response validation runs in two stages:

1. **HTTP status validation**
   - `401` => `SabianaApiAuthError`
   - other `>= 400` => `SabianaApiClientError`
2. **API JSON status validation**
   - `status == 99 or 103` => `SabianaApiAuthError`
   - any non-zero status => `SabianaApiClientError`

This ensures both transport-level and domain-level errors are normalized for upper layers.

### JWT Expiry Parsing

JWT expiration is not trusted as opaque metadata. The integration:

- decodes JWT payload (`base64url`),
- extracts `exp` claim,
- converts it to timezone-aware UTC datetime.

If JWT structure is malformed or `exp` is missing, setup fails with a client error, preventing unsafe token assumptions.

---

## Token Lifecycle Management

The token lifecycle is implemented in `SabianaTokenCoordinator` (`coordinator.py`) and runs on a 60-second update interval.

### Coordinator Responsibilities

- monitor current short/long JWT expiry,
- refresh short token before use when expired,
- perform full re-authentication when long token is expired or renewal fails auth,
- persist updated tokens back into the `ConfigEntry`,
- expose current usable short token as `coordinator.data`.

### Refresh Algorithm

At each update cycle:

1. If **long JWT expired**:
   - perform full authentication using stored credentials.
2. Else if **short JWT expired**:
   - try `renewJwt` using long token.
   - if renew returns auth error, fallback to full authentication.
3. Else:
   - keep current token.

On successful token changes, `async_update_entry(...)` updates the config entry in Home Assistant.

### Failure Behavior

API and network errors become `UpdateFailed`, which is the Home Assistant-native signaling mechanism for coordinator refresh failures.

---

## Climate Entity Model

`climate.py` maps each discovered Sabiana unit into one `SabianaHvacClimateEntity`.

### Entity Capabilities

Supported Home Assistant features:

- HVAC modes: `off`, `cool`, `heat`, `fan_only`
- target temperature (Celsius)
- fan modes (`low`, `medium`, `high`, `auto`)
- swing modes (`Vertical`, `Horizontal`, `45 Degrees`, `Swing`)
- preset modes (`sleep`, `none`)
- turn on / turn off

Entity characteristics:

- `_attr_should_poll = False` (no periodic state fetch per entity)
- `RestoreEntity` support (restores last Home Assistant state after restart)
- optimistic state writing on command execution (`async_write_ha_state()`)

### Command Encoding Pipeline

Whenever state-changing methods are called (for example `async_set_hvac_mode`):

1. Entity updates its internal attributes.
2. Entity builds command payload using:
   - HVAC mode map (`HVAC_MODE_MAP`)
   - fan mode map (`FAN_MODE_MAP`)
   - swing map (`SWING_MODE_MAP`)
   - preset mapping (`sleep` => `"2"`, otherwise `"0"`)
   - target temperature converted from Celsius to hex tenths (`25.0` => `"00fa"`).
3. Entity sends payload through `api.async_send_command(...)`.
4. On success, state is written to Home Assistant.
5. On failure, errors are logged and no automatic rollback is applied.

This design prioritizes command dispatch simplicity and HA UI responsiveness.

---

## Device Discovery and Entity Creation

During config entry setup:

1. the integration calls `async_get_devices(...)`,
2. each returned `SabianaDevice(id, name)` becomes one climate entity,
3. entities are added through `async_add_entities(...)`.

Entity `unique_id` is the Sabiana `idDevice`, enabling stable entity identity in Home Assistant.

---

## Runtime Data Flow

Typical operational flow:

1. User action in Home Assistant UI/automation changes climate setting.
2. Entity converts HA state into Sabiana command payload.
3. Entity retrieves current short token from coordinator state.
4. API layer sends command to Sabiana cloud.
5. If token expired, coordinator refresh logic handles renewal/re-auth on next update cycle.
6. Home Assistant entity state reflects last applied command (optimistic model).

---

## Reliability and Observability

### Reliability Controls

- centralized response validation in API layer,
- explicit auth vs generic error separation,
- retry transport for transient HTTP failures,
- periodic token lifecycle checks,
- fallback from token renewal to full re-login.

### Logging

The integration uses structured logging at different levels:

- `info` for setup/unload and key lifecycle milestones,
- `debug` for API operations and token diagnostics,
- `warning` for recoverable auth/flow issues,
- `exception` for unexpected failures with traceback.

---

## Security Considerations

- Credentials are stored in Home Assistant config entry storage and used only to authenticate against Sabiana cloud.
- Token handling is explicit, with expiry checked from JWT claims.
- Authorization headers:
  - short JWT in `auth`,
  - long JWT in `renewauth` for renewal endpoint.

The integration does not introduce custom cryptographic primitives; it consumes Sabiana-issued JWTs and API contracts.

---

## Testing Strategy

The repository includes unit tests covering the core architecture:

- `tests/test_config_flow.py`
  - successful setup path,
  - error mapping and form behavior.
- `tests/test_api.py`
  - response validation,
  - JWT extraction/parsing,
  - endpoint behavior and error paths.
- `tests/test_coordinator.py`
  - token refresh/re-auth decision logic,
  - update persistence and failure handling.
- `tests/test_climate.py`
  - entity capabilities,
  - payload generation components,
  - command execution behavior and exception handling.

This gives good coverage of integration control flow and token reliability logic.

---

## Current Limitations and Architectural Implications

1. **Optimistic state model**
   - entities represent last commanded state, not guaranteed real device telemetry.

2. **No dedicated real-time state synchronization**
   - there is no explicit periodic device-status pull in the climate entity layer.

3. **Cloud dependency**
   - integration availability depends on Sabiana cloud API reachability and behavior.

4. **Model support scope**
   - compatibility is currently documented as tested primarily on Sabiana Carisma Fly devices.

---

## Recommended Future Enhancements

To evolve the architecture toward stronger operational fidelity:

1. Add real device state polling endpoint integration (if available) and reconcile entity state from cloud telemetry.
2. Introduce command acknowledgment tracking to detect and surface delivery/actuation mismatches.
3. Use `ConfigEntry` options for tunable polling/retry strategy.
4. Improve diagnostics by exposing token/connection health as diagnostic entities or repair issues.
5. Add integration tests for end-to-end startup and command dispatch under Home Assistant test harness.

---

## File-Level Reference Map

- `custom_components/sabiana_hvac/manifest.json` - integration registration metadata.
- `custom_components/sabiana_hvac/config_flow.py` - UI setup and credential/token persistence.
- `custom_components/sabiana_hvac/__init__.py` - config entry setup/unload orchestration.
- `custom_components/sabiana_hvac/api.py` - Sabiana API client and validation layer.
- `custom_components/sabiana_hvac/coordinator.py` - JWT lifecycle coordinator.
- `custom_components/sabiana_hvac/climate.py` - climate entities and command payload generation.
- `custom_components/sabiana_hvac/const.py` - constants and mode mappings.
- `custom_components/sabiana_hvac/models.py` - shared data models.

