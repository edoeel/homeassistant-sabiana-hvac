# Copyright (c) 2026 Edoardo Mistretta

"""Data models for Sabiana HVAC integration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

# Fancoil modes (word 3, low byte), app class E.
MODE_COOL = 0  # MODE_SUMMER
MODE_HEAT = 1  # MODE_WINTER
MODE_AUTO = 2
MODE_FAN_ONLY = 3

MODEL_MELTEMI = "5029"
MODEL_TYPE_RVU = "rvu"


_FAN_CONTINUOUS_MIN = 20
_DEFAULT_SETPOINT_RANGE = (10.0, 30.0)

# Flap positions (word 5, high byte), app labels cloudwm.FlapPosition_N.
FLAP_POSITION_NAMES = {
    0: "Stop swing",
    1: "Summer",
    2: "Winter",
    3: "Full open",
    4: "Swing",
}

# WiFi signal bars (app: DBMToSignalStrength), as (minimum dBm, bars).
_RSSI_BARS = ((-46, 5), (-60, 4), (-72, 3), (-80, 2), (-90, 1))
_RSSI_WARN_BELOW = -72


@dataclass
class JWT:
    """Represents a JWT token with its expiration timestamp."""

    token: str
    expire_at: datetime


@dataclass(frozen=True, slots=True)
class SabianaDeviceState:
    """Decoded fancoil lastData, field by field as in the app (class E).

    Built by protocol.decode_fancoil. The properties at the end translate the
    app fields into derived values (HVAC action, setpoint of the mode).
    """

    raw: str
    model_type: str  # decoder type ("evo", "tmb", ...), see protocol
    controller_model: str  # word 1, uppercase, e.g. "500D"

    # Profile (depends on model, firmware and DIP switches)
    commercial_name: str
    commercial_name_small: str
    fw_type: str | None
    fan_regulation_mode: str | None  # "3A", "2", "10A", "19A" or None
    is_fan_1_to_10: bool
    timers_available: bool | None  # None: not defined by the app for the model
    night_mode_available: bool | None
    flap_present: bool  # profile has a flap and word 5 low byte is not 0
    flap_simple_mode: bool  # only positions 0 and 4 (TMB)
    eco_limited_mode: bool  # 5021 with DIP 0 and 1 off: on/off and fan only

    # Firmware
    fw_release: str  # word 2, "Firmware POW"
    fw_release_est1: str  # word 15, "Firmware ESP" ("Firmware T-MB" on TMB)
    fw_release_est2: str  # word 16, "Firmware DISP"
    config_dip: int  # word 17

    # Word 3
    mode: int
    fan: int  # after the app's read fix-ups (0 -> 1, legacy -> 20/60/110)

    # Word 4
    on: bool  # already False when the remote on/off is active
    request_thermo: bool
    auto_mode_available: bool
    iaq_present: bool
    t2_present: bool
    t3_present: bool
    night_mode_on: bool
    remote_on_off: bool  # unit switched off by the remote contact
    remote_season: bool
    pump_lna_lnc: bool
    resistance_on: bool
    timer_on: bool
    under_sabianet: bool
    window_open: bool

    # Word 5
    flap_position: int | None

    # Words 6-12
    t1: float
    setpoint_summer: float
    setpoint_winter: float
    setpoint_auto: float
    range_summer: tuple[float, float]
    range_winter: tuple[float, float]
    range_auto: float

    # Word 13
    active_alarms: tuple[str, ...]

    # Word 14: device clock, local time of the installation
    day_of_week: int  # 1 = Monday ... 7 = Sunday
    hour: int
    minutes: int

    @property
    def on_alarm(self) -> bool:
        """Return whether at least one applicable alarm is active."""
        return bool(self.active_alarms)

    @property
    def is_door_curtain(self) -> bool:
        """Return whether the unit is a Meltemi air curtain."""
        return self.model_type == "tmb" and self.controller_model == MODEL_MELTEMI

    @property
    def hvac_action(self) -> str | None:
        """Return the HA HVAC action, from the app's mode icon logic."""
        if not self.on:
            return "off"
        if self.mode == MODE_FAN_ONLY:
            return "fan"
        if self.mode not in (MODE_COOL, MODE_HEAT, MODE_AUTO):
            return None
        if not self.request_thermo:
            return "idle"
        # In auto the app infers the direction from T1 vs the auto setpoint;
        # on the Meltemi, mode 2 is "max heating".
        cooling = self.mode == MODE_COOL or (
            self.mode == MODE_AUTO
            and self.controller_model != MODEL_MELTEMI
            and self.t1 > self.setpoint_auto
        )
        return "cooling" if cooling else "heating"

    @property
    def target_temperature(self) -> float | None:
        """Return the setpoint of the current mode (app: currentSet)."""
        if self.mode == MODE_COOL:
            return self.setpoint_summer
        if self.mode == MODE_HEAT:
            return self.setpoint_winter
        if self.mode == MODE_AUTO:
            if self.controller_model == MODEL_MELTEMI:
                return self.setpoint_winter
            return self.setpoint_auto
        return None  # fan only has no setpoint

    def setpoint_range(self, mode: int | None = None) -> tuple[float, float]:
        """Return the (min, max) setpoint allowed in a mode (default: current).

        App: initDataFromDevice, words 10 and 11; 10-30 in the other modes.
        """
        mode = self.mode if mode is None else mode
        limits = {MODE_COOL: self.range_summer, MODE_HEAT: self.range_winter}.get(
            mode, _DEFAULT_SETPOINT_RANGE
        )
        return limits if limits[0] < limits[1] else _DEFAULT_SETPOINT_RANGE

    @property
    def fan_level(self) -> float | None:
        """Return the continuous fan level 1.0-10.0, or None on stepped scales."""
        if self.fan < _FAN_CONTINUOUS_MIN:
            return None
        return (self.fan - 10) / 10

    @property
    def flap_position_name(self) -> str | None:
        """Return the app label of the flap position, if the unit has a flap."""
        if not self.flap_present or self.flap_position is None:
            return None
        return FLAP_POSITION_NAMES.get(self.flap_position)


@dataclass(frozen=True, slots=True)
class SabianaDevice:
    """A device of the account, as returned by getDeviceForUserV2.

    The server fields keep their meaning from the app; state is the decoded
    last_data (None for RVU units, which are not decoded yet, and for
    invalid frames). Socket.IO events replace this record with an updated copy.
    """

    id: str  # idDevice
    name: str  # deviceName, or idDevice when the unit was never renamed
    model_type: str = "evo"  # deviceStateModelType
    group_id: str | None = None
    group_name: str | None = None
    group_shared: bool = False
    from_share: bool = False
    from_group_share: bool = False
    # None when the server did not send connectionUp: treated as online.
    connection_up: bool | None = None
    wifi_fw: str | None = None  # deviceStateFw
    wifi_rssi: int | None = None  # deviceWiFiRSSI, dBm
    fw_update_request: str | None = None
    time_zone: str | None = None
    last_data: str | None = None
    data_valid: bool = False
    state: SabianaDeviceState | None = None

    @property
    def is_rvu(self) -> bool:
        """Return whether the device is an RVU heat recovery unit."""
        return self.model_type == MODEL_TYPE_RVU

    @property
    def online(self) -> bool:
        """Return whether the cloud reports the device as connected."""
        return self.connection_up is not False

    @property
    def controllable(self) -> bool:
        """Return whether the app would let the user control the device.

        The app also requires the Socket.IO channel to be up; that check
        belongs to the caller.
        """
        return self.online and self.data_valid and self.state is not None

    @property
    def wifi_signal(self) -> int | None:
        """Return the WiFi signal in bars 0-5, as shown by the app."""
        if self.wifi_rssi is None or self.wifi_rssi >= 0:
            return None
        for threshold, bars in _RSSI_BARS:
            if self.wifi_rssi >= threshold:
                return bars
        return 0

    @property
    def wifi_weak(self) -> bool:
        """Return whether the app would warn about a weak WiFi signal."""
        return self.wifi_rssi is not None and self.wifi_rssi < _RSSI_WARN_BELOW


@dataclass(frozen=True, slots=True)
class SabianaDeviceList:
    """Parsed body of getDeviceForUserV2."""

    devices: dict[str, SabianaDevice]  # by idDevice, sorted like the app
    last_fw: dict[str, str]  # latest firmware version by model type
    # Envelope "token": a new long JWT the client must store (app: checkResponse)
    rotated_token: str | None = None
