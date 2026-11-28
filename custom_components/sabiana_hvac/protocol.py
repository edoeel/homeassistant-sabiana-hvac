# Copyright (c) 2026 Edoardo Mistretta

"""Decoding of the Sabiana cloud ``lastData`` frame.

This module is a port of the fancoil state model of the official Sabiana WiFi
app (1.8.07, ``assets/public/1361.*.js``: base class ``he``, helper ``G`` and
fancoil class ``E``). The app is the source of truth: keep this module aligned
with it rather than with empirical guesses.

A frame is a hex string of 16-bit *words*, 4 hex characters each. Words are
numbered from 1, as in the app: word ``n`` is ``raw[4n-4:4n]``. The server
sends lowercase hex; parsing is case-insensitive.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace

from .models import (
    MODE_AUTO,
    MODE_COOL,
    MODE_FAN_ONLY,
    MODE_HEAT,
    MODEL_MELTEMI,
    SabianaDeviceState,
)

_LOGGER = logging.getLogger(__name__)

# deviceStateModelType values handled by the fancoil decoder (app:
# createCorrectUnitDataModel). Any other value except "rvu" falls back to "evo".
MODEL_TYPE_RVU = "rvu"
MODEL_TYPE_TMB = "tmb"
FANCOIL_MODEL_TYPES = frozenset({"evo", "crc", "eco", "ntc", "cvp", "tmb", "cfo"})

# Invalid-data markers (app: he.updateData).
_MIN_VALID_LENGTH = 10  # strictly longer than this
_DATA_ERROR_VALUE = "999999"
_DATA_ERROR_PREFIX = "0" * 16

# The app does not check the length; the integration has always required the
# first 9 words (up to setPointAuto). Shorter frames would decode to garbage.
_MIN_FANCOIL_WORDS = 9
_FULL_FANCOIL_WORDS = 17

_SIGN_BIT = 0x8000
_WORD_RANGE = 0x10000

FAN_AUTO = 4
FAN_CONTINUOUS_MIN = 20  # FAN_LINEAR_01_0
_LEGACY_FAN_TO_CONTINUOUS = {1: 20, 2: 60, 3: 110}

_MODELS_REMOTE_ACTIVE_HIGH = frozenset({"500B", "500C"})
_MODELS_SWITCHING_TO_19A = frozenset({"500D", "500E"})
_ESP_FW_TIMERS_5021 = 48  # 0.48
_ESP_FW_TIMERS_5022 = 89  # 0.89

# Alarm bits of word 13: (bit, key, models it applies to or None for all).
_FANCOIL_ALARMS: tuple[tuple[int, str, frozenset[str] | None], ...] = (
    (0, "t1Fault", None),
    (1, "t2Fault", None),
    (2, "t3Fault", None),
    (
        3,
        "condensate",
        frozenset({"5000", "5001", "5002", "5003", "5004", "5005", "500A"}),
    ),
    (5, "TMBProbe", None),
    (6, "timekeeperFault", None),
    (7, "frostAlarm", None),
    (8, "coolNotPossible", frozenset({"5004", "5005", "5006", "5007", "500A"})),
    (9, "comFlapBoardKO", frozenset({"500A"})),
)


# ---------------------------------------------------------------------------
# Profiles (app: first part of E.decode)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Profile:
    """Capabilities of a fancoil model, before the per-frame adjustments."""

    commercial_name: str = "Sabiana unit"
    commercial_name_small: str = "N.D."
    fw_type: str | None = None
    fan_regulation_mode: str | None = None  # "3A", "2", "10A", "19A"
    is_fan_1_to_10: bool = False
    timers_available: bool | None = None  # None: not defined by the app
    night_mode_available: bool | None = None
    flap_present: bool = False
    flap_simple_mode: bool = False  # positions 0 and 4 only
    eco_limited_mode: bool = False


# Non-TMB profiles keyed by controller model (word 1). Timers of 5021 and 5022
# depend on the frame and are computed in _resolve_profile.
_NON_TMB_PROFILES: dict[str, _Profile] = {
    "5020": _Profile(
        commercial_name="Whisper CFF-ECM Touch",
        commercial_name_small="CFF EVO",
        fw_type="evo",
        fan_regulation_mode="19A",
        is_fan_1_to_10=True,
        timers_available=True,
        night_mode_available=True,
    ),
    "5021": _Profile(
        commercial_name="Whisper CFF-ECM ECO",
        commercial_name_small="CFF ECO",
        fw_type="eco",
        fan_regulation_mode="19A",
        is_fan_1_to_10=True,
        timers_available=None,
        night_mode_available=False,
    ),
    "5025": _Profile(
        commercial_name="Carisma ECM",
        commercial_name_small="CRC EVO",
        fw_type="crc",
        fan_regulation_mode="19A",
        is_fan_1_to_10=True,
        timers_available=True,
        night_mode_available=True,
    ),
    "500A": _Profile(
        commercial_name="SkyStar Jumbo",
        commercial_name_small="Jumbo",
        fw_type="ntc",
        fan_regulation_mode="3A",
        timers_available=True,
        night_mode_available=False,
        flap_present=True,
    ),
    "500D": _Profile(
        commercial_name="Carisma Fly",
        commercial_name_small="CVP2",
        fw_type="cvp",
        fan_regulation_mode="3A",
        timers_available=True,
        night_mode_available=True,
        flap_present=True,
    ),
    "500E": _Profile(
        commercial_name="CFF ECM OW",
        commercial_name_small="cfo",
        fw_type="cfo",
        fan_regulation_mode="3A",
        timers_available=True,
        night_mode_available=True,
        flap_present=True,
    ),
    "5022": _Profile(
        commercial_name="Whisper CFF-ECM Touch",
        commercial_name_small="CFF MIX",
        fw_type="evo",
        fan_regulation_mode="19A",
        is_fan_1_to_10=True,
        timers_available=None,
        night_mode_available=False,
    ),
    "5023": _Profile(
        commercial_name="Whisper CFF-ECM ECO",
        commercial_name_small="CFF MIX",
        fw_type="eco",
        fan_regulation_mode="19A",
        is_fan_1_to_10=True,
        timers_available=True,
        night_mode_available=True,
    ),
}
_UNKNOWN_PROFILE = _Profile()

# Every TMB has timers, a simple (0/4) flap and fwType "tmb"; the model code
# only changes the name, the fan scale and the night mode.
_TMB_BASE = _Profile(
    commercial_name="Ventilconvettore/Fan Coil - TMB",
    commercial_name_small="Cassette/FanCoil",
    fw_type="tmb",
    fan_regulation_mode="3A",
    timers_available=True,
    night_mode_available=True,
    flap_present=True,
    flap_simple_mode=True,
)
_TMB_PROFILES: dict[str, _Profile] = {
    "5004": replace(
        _TMB_BASE,
        commercial_name="Carisma Fly - TMB",
        commercial_name_small="CVP",
    ),
    "500B": replace(
        _TMB_BASE,
        commercial_name="Atlas - TMB",
        commercial_name_small="Atlas",
        fan_regulation_mode="10A",
    ),
    "500C": replace(
        _TMB_BASE,
        commercial_name="Janus - TMB",
        commercial_name_small="Janus",
        fan_regulation_mode="10A",
    ),
    "5020": replace(
        _TMB_BASE,
        commercial_name="Whisper CFF-ECM - TMB",
        commercial_name_small="CFF",
        fan_regulation_mode="10A",
    ),
    "5028": replace(
        _TMB_BASE,
        commercial_name="Ventilconvettore/Fan Coil AU - TMB",
        commercial_name_small="AU",
    ),
    "5029": replace(
        _TMB_BASE,
        commercial_name="Meltemi - TMB",
        commercial_name_small="Meltemi",
        fan_regulation_mode="2",
        night_mode_available=False,
    ),
}


# ---------------------------------------------------------------------------
# Word helpers (app: class G)
# ---------------------------------------------------------------------------


class _Frame:
    """Read-only accessor over the words of a frame."""

    __slots__ = ("_words",)

    def __init__(self, raw: str) -> None:
        # int(..., 16) raises ValueError on non-hex characters.
        self._words = [int(raw[i : i + 4], 16) for i in range(0, len(raw) - 3, 4)]

    def __len__(self) -> int:
        return len(self._words)

    def word(self, n: int) -> int:
        """Return unsigned word n (1-indexed). Missing trailing words read 0."""
        return self._words[n - 1] if n <= len(self._words) else 0

    def sword(self, n: int) -> int:
        """Return word n as a signed 16-bit integer (G.getInt / G.modulo)."""
        value = self.word(n)
        return value - _WORD_RANGE if value >= _SIGN_BIT else value

    def hi(self, n: int) -> int:
        """Return the high byte of word n (G.getIntH)."""
        return self.word(n) >> 8

    def lo(self, n: int) -> int:
        """Return the low byte of word n (G.getIntL)."""
        return self.word(n) & 0xFF

    def bit(self, n: int, k: int) -> bool:
        """Return bit k of word n, bit 0 = LSB (G.getBitToBitOK index)."""
        return bool((self.word(n) >> k) & 1)

    def tenths(self, n: int) -> float:
        """Return signed word n divided by 10 (G.getDouble)."""
        return self.sword(n) / 10

    def fw(self, n: int) -> str:
        """Return the firmware version in word n as "H.LL" (G.getFwVersion)."""
        return f"{self.hi(n)}.{self.lo(n):02d}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def is_last_data_valid(raw: str | None) -> bool:
    """Return whether a lastData frame is valid (app: he.updateData).

    Missing or short (<= 10 chars) frames are invalid; "999999" and frames
    starting with 16 zeros are the "DATA-ERROR" markers.
    """
    return (
        isinstance(raw, str)
        and len(raw) > _MIN_VALID_LENGTH
        and raw != _DATA_ERROR_VALUE
        and not raw.startswith(_DATA_ERROR_PREFIX)
    )


def normalize_model_type(model_type: str | None) -> str:
    """Map deviceStateModelType to the decoder type (createCorrectUnitDataModel).

    "crc" is decoded as "evo"; unknown types fall back to "evo" as in the app.
    """
    if model_type == MODEL_TYPE_RVU:
        return MODEL_TYPE_RVU
    if model_type == "crc":
        return "evo"
    if model_type in FANCOIL_MODEL_TYPES:
        return model_type
    _LOGGER.warning(
        "Unknown deviceStateModelType %r, decoding as a fancoil (evo)", model_type
    )
    return "evo"


def decode_fancoil(raw: str, model_type: str = "evo") -> SabianaDeviceState | None:
    """Decode a fancoil lastData frame, or return None if it is not decodable.

    Args:
        raw: lastData hex string, as received from REST or Socket.IO.
        model_type: deviceStateModelType of the device. Only "tmb" changes the
            decoding; for other fancoils the profile depends on word 1 only.

    Returns:
        The decoded state, or None when the frame is invalid (see
        is_last_data_valid), not hex, or too short to hold the setpoints.

    """
    if not is_last_data_valid(raw):
        return None

    try:
        frame = _Frame(raw)
    except ValueError:
        _LOGGER.warning("lastData is not a hex string: %s", raw)
        return None

    if len(frame) < _MIN_FANCOIL_WORDS:
        _LOGGER.warning(
            "lastData too short: %d words (minimum %d): %s",
            len(frame),
            _MIN_FANCOIL_WORDS,
            raw,
        )
        return None
    if len(frame) < _FULL_FANCOIL_WORDS:
        _LOGGER.debug(
            "lastData has %d words instead of %d, missing words read as 0: %s",
            len(frame),
            _FULL_FANCOIL_WORDS,
            raw,
        )

    return _decode_fancoil_frame(raw, frame, normalize_model_type(model_type))


def decode_device_data(
    model_type: str,
    raw: str | None,
    previous: SabianaDeviceState | None = None,
) -> tuple[SabianaDeviceState | None, bool]:
    """Decode the lastData of a device into (state, data_valid).

    Mirrors he.updateData: an invalid frame leaves the previous decoded
    state in place but marks the data as not valid. RVU frames are only
    validated, not decoded.
    """
    if model_type == MODEL_TYPE_RVU:
        return None, is_last_data_valid(raw)
    state = decode_fancoil(raw, model_type) if raw else None
    if state is None:
        return previous, False
    return state, True


# ---------------------------------------------------------------------------
# Decoding (app: E.decode)
# ---------------------------------------------------------------------------


def _decode_fancoil_frame(
    raw: str, frame: _Frame, model_type: str
) -> SabianaDeviceState:
    controller_model = raw[0:4].upper()
    esp_fw_number = 100 * frame.hi(15) + frame.lo(15)
    config_dip = frame.word(17)
    profile = _resolve_profile(model_type, controller_model, esp_fw_number, config_dip)

    # Word 4: status flags.
    on = frame.bit(4, 0)
    remote_bit = frame.bit(4, 8)
    remote_on_off = (
        remote_bit if controller_model in _MODELS_REMOTE_ACTIVE_HIGH else not remote_bit
    )
    if on and remote_on_off:
        on = False
    under_sabianet = frame.bit(4, 13)
    timers_available = profile.timers_available
    if under_sabianet and timers_available:
        timers_available = False

    # Word 5: flap. Only profiles with a flap look at it.
    flap_present = profile.flap_present
    flap_position: int | None = None
    if flap_present:
        if frame.lo(5) == 1:
            flap_position = frame.hi(5)
        if frame.lo(5) == 0:
            flap_present = False

    # Word 3: mode (low byte) and fan (high byte).
    mode = frame.lo(3)
    fan, fan_regulation_mode, is_fan_1_to_10 = _normalize_fan(
        frame.hi(3),
        controller_model,
        profile.fan_regulation_mode,
        is_fan_1_to_10=profile.is_fan_1_to_10,
        raw=raw,
    )

    clock = frame.word(14)

    return SabianaDeviceState(
        raw=raw,
        model_type=model_type,
        controller_model=controller_model,
        commercial_name=profile.commercial_name,
        commercial_name_small=profile.commercial_name_small,
        fw_type=profile.fw_type,
        fan_regulation_mode=fan_regulation_mode,
        is_fan_1_to_10=is_fan_1_to_10,
        timers_available=timers_available,
        night_mode_available=profile.night_mode_available,
        flap_present=flap_present,
        flap_simple_mode=profile.flap_simple_mode,
        eco_limited_mode=profile.eco_limited_mode,
        fw_release=frame.fw(2),
        fw_release_est1=frame.fw(15),
        fw_release_est2=frame.fw(16),
        config_dip=config_dip,
        mode=mode,
        fan=fan,
        on=on,
        request_thermo=frame.bit(4, 1),
        auto_mode_available=frame.bit(4, 2),
        iaq_present=frame.bit(4, 3),
        t2_present=frame.bit(4, 4),
        t3_present=frame.bit(4, 5),
        night_mode_on=frame.bit(4, 7),
        remote_on_off=remote_on_off,
        remote_season=frame.bit(4, 9),
        pump_lna_lnc=frame.bit(4, 10),
        resistance_on=frame.bit(4, 11),
        timer_on=frame.bit(4, 12),
        under_sabianet=under_sabianet,
        window_open=frame.bit(4, 14),
        flap_position=flap_position,
        t1=frame.tenths(6),
        setpoint_summer=frame.tenths(7),
        setpoint_winter=frame.tenths(8),
        setpoint_auto=frame.tenths(9),
        range_summer=((frame.lo(10) + 100) / 10, (frame.hi(10) + 100) / 10),
        range_winter=((frame.lo(11) + 100) / 10, (frame.hi(11) + 100) / 10),
        range_auto=frame.tenths(12),
        active_alarms=_decode_alarms(frame, controller_model),
        day_of_week=clock & 0x7,
        hour=(clock >> 3) & 0x1F,
        minutes=(clock >> 8) & 0x3F,
    )


def _resolve_profile(
    model_type: str, controller_model: str, esp_fw_number: int, config_dip: int
) -> _Profile:
    """Return the profile of a fancoil (app: first half of E.decode)."""
    if model_type == MODEL_TYPE_TMB:
        return _TMB_PROFILES.get(controller_model, _TMB_BASE)

    profile = _NON_TMB_PROFILES.get(controller_model, _UNKNOWN_PROFILE)
    if controller_model == "5021":
        if config_dip & 0x3:  # DIP 0 or DIP 1
            return replace(
                profile, timers_available=esp_fw_number >= _ESP_FW_TIMERS_5021
            )
        return replace(profile, timers_available=False, eco_limited_mode=True)
    if controller_model == "5022":
        return replace(profile, timers_available=esp_fw_number >= _ESP_FW_TIMERS_5022)
    return profile


def _normalize_fan(
    fan: int,
    controller_model: str,
    fan_regulation_mode: str | None,
    *,
    is_fan_1_to_10: bool,
    raw: str,
) -> tuple[int, str | None, bool]:
    """Apply the app's read-side fan fix-ups (end of E.decode)."""
    if fan == 0:
        _LOGGER.warning("Fan speed 0 in lastData, reading it as 1: %s", raw)
        fan = 1
    if controller_model in _MODELS_SWITCHING_TO_19A and fan >= FAN_CONTINUOUS_MIN:
        is_fan_1_to_10, fan_regulation_mode = True, "19A"
    if fan < FAN_CONTINUOUS_MIN and is_fan_1_to_10:
        fan = _LEGACY_FAN_TO_CONTINUOUS.get(fan, fan)
    return fan, fan_regulation_mode, is_fan_1_to_10


def _decode_alarms(frame: _Frame, controller_model: str) -> tuple[str, ...]:
    return tuple(
        key
        for bit, key, models in _FANCOIL_ALARMS
        if frame.bit(13, bit) and (models is None or controller_model in models)
    )


# ---------------------------------------------------------------------------
# Commands (app: doSendCmd of the single fancoil page)
# ---------------------------------------------------------------------------

COMMAND_START = 2304  # Modbus holding register 0x0900, 5 registers
_COMMAND_MODE_OFF = 4
_REGISTER_FLAP_ABSENT = "FF00"
_REGISTER_CLOCK_UNCHANGED = "FFFF"  # the clock is only written over BLE


@dataclass(frozen=True, slots=True)
class FancoilCommand:
    """The values sent with a fancoil command (start 2304, 5 registers).

    The app always sends the full block, built from the values on screen;
    timer and night bits come from the current state. Build it with
    from_state and change one field at a time.
    """

    on: bool
    mode: int
    fan: int
    setpoint: float
    flap_position: int | None  # None: unit without flap (register FF00)
    timer_on: bool
    night_on: bool

    @classmethod
    def from_state(cls, state: SabianaDeviceState) -> FancoilCommand:
        """Return the command leaving the unit as it is (app: initDataFromDevice)."""
        setpoint = state.target_temperature
        return cls(
            on=state.on,
            mode=state.mode,
            fan=state.fan,
            setpoint=0.0 if setpoint is None else setpoint,
            flap_position=state.flap_position if state.flap_present else None,
            timer_on=state.timer_on,
            night_on=state.night_mode_on,
        )

    def with_mode(self, state: SabianaDeviceState, mode: int) -> FancoilCommand:
        """Switch mode, loading the setpoint the device stores for it.

        App: touchEndFromWheel loads the summer / winter setpoint and 0 in fan
        only. In auto the app keeps the setpoint on screen; here the auto
        setpoint is loaded explicitly (winter setpoint on the Meltemi), as
        Home Assistant shows the setpoint of the current mode.
        """
        if mode == MODE_COOL:
            setpoint = state.setpoint_summer
        elif mode == MODE_HEAT:
            setpoint = state.setpoint_winter
        elif mode == MODE_AUTO:
            setpoint = (
                state.setpoint_winter
                if state.controller_model == MODEL_MELTEMI
                else state.setpoint_auto
            )
        else:
            setpoint = 0.0
        return replace(self, on=True, mode=mode, setpoint=setpoint)

    def to_hex(self) -> str:
        """Encode the 5 registers, uppercase like the app (G.setRaw)."""
        register_1 = (self.mode if self.on else _COMMAND_MODE_OFF) + 256 * self.fan
        setpoint = 0.0 if self.mode == MODE_FAN_ONLY else self.setpoint
        # The GUI moves in 0.5 °C steps; round to avoid fractional tenths.
        register_2 = round(round(setpoint * 2) / 2 * 10)
        register_3 = (
            _REGISTER_FLAP_ABSENT
            if self.flap_position is None
            else _word_hex(1 + 256 * self.flap_position)
        )
        register_5 = (1 if self.timer_on else 0) | (2 if self.night_on else 0)
        return (
            _word_hex(register_1)
            + _word_hex(register_2)
            + register_3
            + _REGISTER_CLOCK_UNCHANGED
            + _word_hex(register_5)
        )

    def is_applied(self, state: SabianaDeviceState) -> bool:
        """Return whether a frame shows the command as applied.

        App: updateData unlocks the screen when on, setpoint, fan and mode
        match; night mode and flap are compared too, since Home Assistant
        shows them from the same pending command.
        """
        if (state.on, state.mode, state.fan) != (self.on, self.mode, self.fan):
            return False
        if (
            self.mode != MODE_FAN_ONLY
            and state.target_temperature != round(self.setpoint * 2) / 2
        ):
            return False
        flap = state.flap_position if state.flap_present else None
        return state.night_mode_on == self.night_on and flap == self.flap_position


def _word_hex(value: int) -> str:
    """Return a 16-bit two's complement word as 4 uppercase hex chars (G.setInt)."""
    return f"{value & 0xFFFF:04X}"


# ---------------------------------------------------------------------------
# Fan scales (app: fanRegulationMode of the profile)
# ---------------------------------------------------------------------------

FAN_MODE_AUTO = "auto"
_STEPPED_SCALES: dict[str, tuple[tuple[str, int], ...]] = {
    "3A": (("low", 1), ("medium", 2), ("high", 3), (FAN_MODE_AUTO, FAN_AUTO)),
    "2": (("low", 1), ("high", 3)),  # Meltemi: min and max, no auto
}
_CONTINUOUS_STEPS = {"10A": 10, "19A": 5}  # in tenths of a level


def fan_scale(state: SabianaDeviceState) -> tuple[tuple[str, int], ...]:
    """Return the (name, value) fan speeds the unit accepts.

    Continuous scales are named by their level ("1" ... "10", with "1.5"
    steps on 19A): fan value = 10 * level + 10. Models without a defined
    scale get 3A, the safest choice.
    """
    scale = state.fan_regulation_mode or "3A"
    if scale in _STEPPED_SCALES:
        return _STEPPED_SCALES[scale]
    step = _CONTINUOUS_STEPS.get(scale, 10)
    levels = tuple(
        (f"{value / 10 - 1:g}", value) for value in range(FAN_CONTINUOUS_MIN, 111, step)
    )
    return ((FAN_MODE_AUTO, FAN_AUTO), *levels)


def fan_mode_name(state: SabianaDeviceState, fan: int) -> str:
    """Return the name of a fan value on the unit's scale."""
    for name, value in fan_scale(state):
        if value == fan:
            return name
    if fan >= FAN_CONTINUOUS_MIN:
        return f"{fan / 10 - 1:g}"
    return str(fan)
