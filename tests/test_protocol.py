# Copyright (c) 2026 Edoardo Mistretta

"""Tests for the lastData decoder (port of the app's fancoil model)."""

from dataclasses import replace
from typing import TYPE_CHECKING, Any

import pytest

from custom_components.sabiana_hvac.models import MODE_AUTO, MODE_HEAT
from custom_components.sabiana_hvac.protocol import (
    FancoilCommand,
    decode_device_data,
    decode_fancoil,
    fan_mode_name,
    fan_scale,
    is_last_data_valid,
    normalize_model_type,
)

from .frames import (
    FLAG_NIGHT,
    FLAG_ON,
    FLAG_REMOTE,
    FLAG_REQUEST,
    FLAG_SABIANET,
    FLAG_TIMER,
    FLAG_WINDOW,
    FLAGS_ON,
    build_frame,
)

if TYPE_CHECKING:
    from custom_components.sabiana_hvac.models import SabianaDeviceState

# Real Carisma Fly 500D frames from issue #88: both units off, night mode on.
FRAME_500D_WORDS = (
    "500d",
    "002b",
    "0400",
    "01c4",
    "0001",
    "0124",
    "00f5",
    "0104",
    "00dc",
    "c800",
    "c800",
    "0000",
    "0000",
    "467b",
    "002b",
    "0000",
    "0004",
    "0000",
    "0000",
    "0000",
)
FRAME_500D_OFF = "".join(FRAME_500D_WORDS)
WORD_FLAGS = 4
FRAME_500D_TWIN = "".join(
    word if n != WORD_FLAGS else "01e0" for n, word in enumerate(FRAME_500D_WORDS, 1)
)


def decode(raw: str, model_type: str = "evo") -> SabianaDeviceState:
    """Decode a frame that must be valid."""
    state = decode_fancoil(raw, model_type)
    assert state is not None
    return state


def fields(state: SabianaDeviceState, *names: str) -> dict[str, Any]:
    """Return the named attributes of a state, for compact assertions."""
    return {name: getattr(state, name) for name in names}


class TestRealFrame:
    """The annotated frame of the v2 protocol document, appendix A."""

    def test_decodes_like_the_app(self) -> None:
        """Every decoded field matches the app's rules."""
        state = decode(FRAME_500D_OFF, "cvp")
        assert fields(
            state,
            "controller_model",
            "commercial_name",
            "fan_regulation_mode",
            "fw_release",
            "fw_release_est1",
            "fw_release_est2",
            "mode",
            "fan",
            "on",
            "request_thermo",
            "auto_mode_available",
            "night_mode_on",
            "remote_on_off",
            "flap_present",
            "flap_position",
            "t1",
            "setpoint_summer",
            "setpoint_winter",
            "setpoint_auto",
            "range_summer",
            "range_winter",
            "active_alarms",
            "day_of_week",
            "hour",
            "minutes",
            "config_dip",
        ) == {
            "controller_model": "500D",
            "commercial_name": "Carisma Fly",
            "fan_regulation_mode": "3A",
            "fw_release": "0.43",
            "fw_release_est1": "0.43",
            "fw_release_est2": "0.00",
            "mode": 0,
            "fan": 4,
            "on": False,
            "request_thermo": False,
            "auto_mode_available": True,
            "night_mode_on": True,
            "remote_on_off": False,
            "flap_present": True,
            "flap_position": 0,
            "t1": 29.2,
            "setpoint_summer": 24.5,
            "setpoint_winter": 26.0,
            "setpoint_auto": 22.0,
            "range_summer": (10.0, 30.0),
            "range_winter": (10.0, 30.0),
            "active_alarms": (),
            "day_of_week": 3,
            "hour": 15,
            "minutes": 6,
            "config_dip": 4,
        }

    def test_home_assistant_view(self) -> None:
        """The HA-facing properties of the real frame."""
        state = decode(FRAME_500D_OFF, "cvp")
        assert fields(
            state,
            "hvac_action",
            "target_temperature",
            "flap_position_name",
        ) == {
            "hvac_action": "off",
            "target_temperature": 24.5,
            "flap_position_name": "Stop swing",
        }

    def test_twin_unit_has_no_auto_mode(self) -> None:
        """Auto availability is per unit: word 4 = 01e0 on the twin unit."""
        state = decode(FRAME_500D_TWIN, "cvp")
        assert state.auto_mode_available is False
        assert state.t3_present is True
        assert state.on is False

    def test_case_insensitive(self) -> None:
        """The server sends lowercase hex; uppercase decodes the same."""
        upper = decode(FRAME_500D_OFF.upper(), "cvp")
        lower = decode(FRAME_500D_OFF, "cvp")
        assert upper.raw == FRAME_500D_OFF.upper()
        assert replace(upper, raw=lower.raw) == lower


class TestValidity:
    """he.updateData rules."""

    @pytest.mark.parametrize(
        "raw",
        [None, "", "0123456789", "999999", "0" * 16 + FRAME_500D_OFF[16:]],
    )
    def test_invalid(self, raw: str | None) -> None:
        """Missing, short and DATA-ERROR frames are not valid."""
        assert is_last_data_valid(raw) is False
        assert decode_fancoil(raw, "evo") is None  # type: ignore[arg-type]

    def test_valid(self) -> None:
        """A normal frame is valid."""
        assert is_last_data_valid(FRAME_500D_OFF) is True

    def test_not_hex(self) -> None:
        """A frame with non-hex characters cannot be decoded."""
        assert decode_fancoil("zz" * 40, "evo") is None

    def test_too_short_for_setpoints(self) -> None:
        """Fewer than 9 words cannot hold the setpoints."""
        assert decode_fancoil(build_frame(words=8), "evo") is None

    def test_missing_trailing_words_read_zero(self) -> None:
        """A 9-word frame decodes, with the missing words as 0."""
        state = decode(build_frame(words=9))
        assert fields(state, "setpoint_auto", "active_alarms", "fw_release_est1") == {
            "setpoint_auto": 22.0,
            "active_alarms": (),
            "fw_release_est1": "0.00",
        }


class TestTemperatures:
    """Signed 16-bit temperatures and per-mode setpoints."""

    def test_negative_and_zero_room_temperature(self) -> None:
        """T1 is signed (two's complement); 0 °C is a real reading."""
        assert decode(build_frame(t1=-20)).t1 == -2.0  # noqa: PLR2004
        assert decode(build_frame(t1=0)).t1 == 0.0

    @pytest.mark.parametrize(
        ("mode", "expected"),
        [(0, 24.0), (1, 20.0), (2, 22.0), (3, None)],
    )
    def test_setpoint_follows_mode(self, mode: int, expected: float | None) -> None:
        """Cool: summer, heat: winter, auto: auto, fan only: none."""
        assert decode(build_frame(mode=mode)).target_temperature == expected

    def test_meltemi_auto_uses_winter_setpoint(self) -> None:
        """On the Meltemi, mode 2 is max heating and shows the winter setpoint."""
        state = decode(build_frame(model="5029", mode=2), "tmb")
        assert state.is_door_curtain is True
        assert state.target_temperature == 20.0  # noqa: PLR2004

    def test_setpoint_ranges(self) -> None:
        """Word 10/11: min = (L+100)/10, max = (H+100)/10; auto is 10-30."""
        state = decode(build_frame(mode=0, range_summer=0xB40A))
        assert state.setpoint_range() == (11.0, 28.0)
        assert state.setpoint_range(MODE_HEAT) == (10.0, 30.0)  # c800
        assert state.setpoint_range(MODE_AUTO) == (10.0, 30.0)
        assert decode(build_frame(range_summer=0)).setpoint_range(0) == (10.0, 30.0)


class TestOnOff:
    """Bit 0 of word 4 and the remote on/off contact (bit 8)."""

    def test_on(self) -> None:
        """Bit 0 set and remote not active: on."""
        state = decode(build_frame(mode=1))
        assert (state.on, state.mode) == (True, 1)

    def test_remote_active_low_forces_off(self) -> None:
        """On normal models the remote is active when bit 8 is 0."""
        state = decode(build_frame(flags=FLAG_ON))
        assert (state.on, state.remote_on_off) == (False, True)

    @pytest.mark.parametrize("model", ["500B", "500C"])
    def test_remote_active_high_on_atlas_janus(self, model: str) -> None:
        """On 500B/500C the polarity is inverted."""
        off = decode(build_frame(model=model, flags=FLAG_ON | FLAG_REMOTE), "tmb")
        on = decode(build_frame(model=model, flags=FLAG_ON), "tmb")
        assert (off.on, off.remote_on_off) == (False, True)
        assert (on.on, on.remote_on_off) == (True, False)


class TestHvacAction:
    """Mode icon logic of the app."""

    @pytest.mark.parametrize(
        ("mode", "flags", "t1", "expected"),
        [
            (1, FLAGS_ON & ~FLAG_ON, 225, "off"),
            (3, FLAGS_ON, 225, "fan"),
            (0, FLAGS_ON, 225, "idle"),
            (1, FLAGS_ON, 225, "idle"),
            (0, FLAGS_ON | FLAG_REQUEST, 225, "cooling"),
            (1, FLAGS_ON | FLAG_REQUEST, 225, "heating"),
            (2, FLAGS_ON | FLAG_REQUEST, 230, "cooling"),  # T1 > auto setpoint
            (2, FLAGS_ON | FLAG_REQUEST, 220, "heating"),  # T1 == auto setpoint
            (2, FLAGS_ON, 230, "idle"),  # neutral zone
        ],
    )
    def test_action(self, mode: int, flags: int, t1: int, expected: str) -> None:
        """hvac_action from on, mode, requestThermo and T1."""
        assert decode(build_frame(mode=mode, flags=flags, t1=t1)).hvac_action == (
            expected
        )

    def test_meltemi_auto_is_heating(self) -> None:
        """Meltemi mode 2 heats regardless of T1."""
        state = decode(
            build_frame(model="5029", mode=2, flags=FLAGS_ON | FLAG_REQUEST, t1=300),
            "tmb",
        )
        assert state.hvac_action == "heating"


class TestFan:
    """Fan scale and read fix-ups."""

    def test_zero_reads_as_one(self) -> None:
        """A fan of 0 is an error: the app reads it as 1."""
        assert decode(build_frame(fan=0)).fan == 1

    @pytest.mark.parametrize(("legacy", "expected"), [(1, 20), (2, 60), (3, 110)])
    def test_legacy_values_on_continuous_models(
        self, legacy: int, expected: int
    ) -> None:
        """19A models convert legacy 1/2/3 into 1/10, 5/10, 10/10."""
        state = decode(build_frame(model="5020", fan=legacy))
        assert (state.fan, state.fan_regulation_mode) == (expected, "19A")

    def test_auto_stays_auto_on_continuous_models(self) -> None:
        """4 is auto on every scale."""
        state = decode(build_frame(model="5020", fan=4))
        assert (state.fan, fan_mode_name(state, 4), state.fan_level) == (
            4,
            "auto",
            None,
        )

    def test_stepped_models_keep_legacy_values(self) -> None:
        """3A models keep 1/2/3 (e.g. 500D reports 0x01 after a LOW command)."""
        state = decode(build_frame(model="500D", fan=1), "cvp")
        assert (state.fan, fan_mode_name(state, 1), state.fan_regulation_mode) == (
            1,
            "low",
            "3A",
        )

    def test_500d_switches_to_19a(self) -> None:
        """500D/500E with a fan >= 20 use the continuous scale."""
        state = decode(build_frame(model="500D", fan=65), "cvp")
        assert (state.fan_regulation_mode, state.is_fan_1_to_10) == ("19A", True)
        assert (state.fan_level, fan_mode_name(state, state.fan)) == (5.5, "5.5")

    def test_tmb_10a_does_not_convert_legacy(self) -> None:
        """TMB profiles never set isFan1to10, even on the 10A scale."""
        state = decode(build_frame(model="500B", fan=2, flags=FLAG_ON), "tmb")
        assert (state.fan, state.fan_regulation_mode) == (2, "10A")


class TestFanScale:
    """Fan speeds offered and accepted per scale (fanRegulationMode)."""

    def test_3a(self) -> None:
        """3A: min, medium, max and auto."""
        state = decode(build_frame(model="500D"), "cvp")
        assert fan_scale(state) == (("low", 1), ("medium", 2), ("high", 3), ("auto", 4))

    def test_meltemi_has_two_speeds(self) -> None:
        """Meltemi (scale 2): min and max, no auto."""
        state = decode(build_frame(model="5029", fan=1), "tmb")
        assert fan_scale(state) == (("low", 1), ("high", 3))

    def test_10a(self) -> None:
        """10A: auto and levels 1-10 (20..110 step 10)."""
        scale = fan_scale(decode(build_frame(model="500B", flags=FLAG_ON), "tmb"))
        assert scale[0] == ("auto", 4)
        assert scale[1:] == tuple((f"{n}", 10 * n + 10) for n in range(1, 11))

    def test_19a(self) -> None:
        """19A: auto and levels 1-10 in 0.5 steps (20..110 step 5)."""
        scale = dict(fan_scale(decode(build_frame(model="5020"))))
        assert len(scale) == 20  # noqa: PLR2004
        assert (scale["1"], scale["5.5"], scale["10"], scale["auto"]) == (
            20,
            65,
            110,
            4,
        )

    def test_unknown_model_uses_3a(self) -> None:
        """Models without a scale get the safest one."""
        assert fan_scale(decode(build_frame(model="5001")))[0] == ("low", 1)

    def test_names_of_values_off_the_scale(self) -> None:
        """Values outside the scale still get a readable name."""
        state = decode(build_frame(model="500B", flags=FLAG_ON), "tmb")
        assert (fan_mode_name(state, 25), fan_mode_name(state, 2)) == ("1.5", "2")


class TestFancoilCommand:
    """The 2304 block, checked against the examples of the protocol doc."""

    @pytest.mark.parametrize(
        ("changes", "expected"),
        [
            # on, heat, 21.5 °C, fan auto, no flap, timer and night off
            ({}, "040100D7FF00FFFF0000"),
            # off, current fan 4
            ({"on": False}, "040400D7FF00FFFF0000"),
            # cool, 24.0 °C, fan 5.5/10 (65), night on
            (
                {"mode": 0, "fan": 65, "setpoint": 24.0, "night_on": True},
                "410000F0FF00FFFF0002",
            ),
            # Jumbo, heat, 20 °C, fan medium, flap swing
            ({"fan": 2, "setpoint": 20.0, "flap_position": 4}, "020100C80401FFFF0000"),
            # 500D, cool, 24.5 °C, fan auto, flap stop swing, night and timer on
            (
                {
                    "mode": 0,
                    "setpoint": 24.5,
                    "flap_position": 0,
                    "timer_on": True,
                    "night_on": True,
                },
                "040000F50001FFFF0003",
            ),
            # fan only: setpoint 0
            ({"mode": 3, "fan": 1, "setpoint": 22.0}, "01030000FF00FFFF0000"),
            # setpoint rounded to 0.5 °C
            ({"setpoint": 21.3}, "040100D7FF00FFFF0000"),
        ],
    )
    def test_to_hex(self, changes: dict[str, Any], expected: str) -> None:
        """Registers 2304-2308, uppercase."""
        base = FancoilCommand(
            on=True,
            mode=1,
            fan=4,
            setpoint=21.5,
            flap_position=None,
            timer_on=False,
            night_on=False,
        )
        assert replace(base, **changes).to_hex() == expected

    def test_from_state_keeps_the_unit_as_it_is(self) -> None:
        """Timer and night come from the state; no flap -> None."""
        state = decode(
            build_frame(model="5020", mode=1, flags=FLAGS_ON | FLAG_TIMER | FLAG_NIGHT)
        )
        command = FancoilCommand.from_state(state)
        assert command == FancoilCommand(
            on=True,
            mode=1,
            fan=4,
            setpoint=20.0,
            flap_position=None,
            timer_on=True,
            night_on=True,
        )
        assert command.is_applied(state)
        # The timer bit survives any change: HA never switches it off.
        assert replace(command, fan=20).to_hex().endswith("0003")

    def test_from_state_with_flap(self) -> None:
        """A unit with a flap sends its position."""
        state = decode(FRAME_500D_OFF, "cvp")
        command = FancoilCommand.from_state(state)
        assert (command.on, command.flap_position, command.setpoint) == (False, 0, 24.5)
        assert command.to_hex() == "040400F50001FFFF0002"

    @pytest.mark.parametrize(
        ("model_type", "model", "mode", "setpoint"),
        [
            ("evo", "500D", 0, 24.0),  # summer setpoint
            ("evo", "500D", 1, 20.0),  # winter setpoint
            ("evo", "500D", 2, 22.0),  # auto setpoint
            ("evo", "500D", 3, 0.0),
            ("tmb", "5029", 2, 20.0),  # Meltemi max heating: winter setpoint
        ],
    )
    def test_with_mode_loads_the_mode_setpoint(
        self, model_type: str, model: str, mode: int, setpoint: float
    ) -> None:
        """Changing mode turns the unit on with the setpoint of that mode."""
        state = decode(build_frame(model=model, mode=1, flags=FLAG_REMOTE), model_type)
        command = FancoilCommand.from_state(state).with_mode(state, mode)
        assert (command.on, command.mode, command.setpoint) == (True, mode, setpoint)

    def test_is_applied(self) -> None:
        """A frame matching on, mode, fan, setpoint, night and flap confirms."""
        state = decode(build_frame(mode=1, setpoint_winter=215))
        command = FancoilCommand.from_state(state)
        assert command.is_applied(state)
        assert not replace(command, setpoint=22.0).is_applied(state)
        assert not replace(command, fan=1).is_applied(state)
        assert not replace(command, on=False).is_applied(state)
        assert not replace(command, night_on=True).is_applied(state)
        # in fan only the setpoint is not compared
        fan_only = decode(build_frame(mode=3))
        assert replace(FancoilCommand.from_state(fan_only), setpoint=30.0).is_applied(
            fan_only
        )


class TestFlap:
    """Word 5 is read only when the profile has a flap."""

    def test_full_flap(self) -> None:
        """500D: low byte 1 = present, high byte = position."""
        state = decode(build_frame(model="500D", flap=0x0401), "cvp")
        assert (state.flap_present, state.flap_position) == (True, 4)
        assert (state.flap_simple_mode, state.flap_position_name) == (False, "Swing")

    def test_flap_absent_on_unit(self) -> None:
        """Low byte 0 removes the flap even if the profile has one."""
        state = decode(build_frame(model="500D", flap=0x0400), "cvp")
        assert (state.flap_present, state.flap_position) == (False, None)

    def test_flap_ignored_without_profile_flap(self) -> None:
        """Whisper (5020) has no flap: word 5 is ignored."""
        state = decode(build_frame(model="5020", flap=0x0401))
        assert (state.flap_present, state.flap_position_name) == (False, None)

    def test_tmb_simple_flap(self) -> None:
        """Every TMB has a simple 0/4 flap."""
        state = decode(build_frame(model="5004", flap=0x0401), "tmb")
        assert (state.flap_present, state.flap_simple_mode) == (True, True)


class TestProfiles:
    """Model-dependent capabilities."""

    def test_tmb_branch_depends_on_model_type(self) -> None:
        """5020 is a Whisper EVO, or a Whisper TMB with deviceStateModelType tmb."""
        evo = decode(build_frame(model="5020"), "evo")
        tmb = decode(build_frame(model="5020"), "tmb")
        assert (evo.commercial_name, evo.fan_regulation_mode) == (
            "Whisper CFF-ECM Touch",
            "19A",
        )
        assert (tmb.commercial_name, tmb.fan_regulation_mode, tmb.fw_type) == (
            "Whisper CFF-ECM - TMB",
            "10A",
            "tmb",
        )

    def test_unknown_tmb_model(self) -> None:
        """Unknown TMB codes get the generic TMB profile."""
        state = decode(build_frame(model="50FF"), "tmb")
        assert state.commercial_name == "Ventilconvettore/Fan Coil - TMB"

    def test_unknown_non_tmb_model(self) -> None:
        """Unknown non-TMB codes: "Sabiana unit", capabilities undefined."""
        state = decode(build_frame(model="5001"))
        assert fields(
            state, "commercial_name", "fan_regulation_mode", "timers_available"
        ) == {
            "commercial_name": "Sabiana unit",
            "fan_regulation_mode": None,
            "timers_available": None,
        }

    def test_5021_limited_mode_without_dip(self) -> None:
        """CFF ECO with DIP 0 and 1 off: reduced mode, no timers."""
        state = decode(build_frame(model="5021", dip=0))
        assert (state.eco_limited_mode, state.timers_available) == (True, False)

    @pytest.mark.parametrize(("fw", "timers"), [(0x002F, False), (0x0030, True)])
    def test_5021_timers_need_esp_048(self, fw: int, timers: bool) -> None:  # noqa: FBT001
        """With a DIP on, timers need ESP firmware >= 0.48."""
        state = decode(build_frame(model="5021", dip=0x1, fw_esp=fw))
        assert (state.eco_limited_mode, state.timers_available) == (False, timers)

    @pytest.mark.parametrize(("fw", "timers"), [(0x0058, False), (0x0059, True)])
    def test_5022_timers_need_esp_089(self, fw: int, timers: bool) -> None:  # noqa: FBT001
        """CFF MIX timers need ESP firmware >= 0.89."""
        assert decode(build_frame(model="5022", fw_esp=fw)).timers_available is timers

    def test_sabianet_disables_timers(self) -> None:
        """Units under Sabianet have no timers."""
        state = decode(build_frame(model="500D", flags=FLAGS_ON | FLAG_SABIANET))
        assert (state.under_sabianet, state.timers_available) == (True, False)

    def test_status_flags(self) -> None:
        """Timer, window open and night flags of word 4."""
        state = decode(
            build_frame(flags=FLAGS_ON | FLAG_TIMER | FLAG_WINDOW | FLAG_NIGHT)
        )
        assert (state.timer_on, state.window_open, state.night_mode_on) == (
            True,
            True,
            True,
        )


class TestAlarms:
    """Word 13, filtered by model."""

    def test_common_alarms(self) -> None:
        """T1 fault and frost apply to every model."""
        state = decode(build_frame(model="500D", alarms=0b1000_0001), "cvp")
        assert state.active_alarms == ("t1Fault", "frostAlarm")
        assert state.on_alarm is True

    def test_model_specific_alarms(self) -> None:
        """Condensate (bit 3) and flap board (bit 9) only on listed models."""
        bits = (1 << 3) | (1 << 9)
        assert decode(build_frame(model="500D", alarms=bits)).active_alarms == ()
        assert decode(build_frame(model="500A", alarms=bits)).active_alarms == (
            "condensate",
            "comFlapBoardKO",
        )


class TestModelType:
    """createCorrectUnitDataModel mapping."""

    @pytest.mark.parametrize(
        ("model_type", "expected"),
        [
            ("evo", "evo"),
            ("crc", "evo"),
            ("tmb", "tmb"),
            ("cvp", "cvp"),
            ("rvu", "rvu"),
            ("xyz", "evo"),
            (None, "evo"),
        ],
    )
    def test_normalize(self, model_type: str | None, expected: str) -> None:
        """Unknown types fall back to evo, like the app."""
        assert normalize_model_type(model_type) == expected


class TestDecodeDeviceData:
    """decode_device_data, shared by REST reads and Socket.IO events."""

    def test_valid_frame(self) -> None:
        """A valid frame replaces the state."""
        state, valid = decode_device_data("cvp", FRAME_500D_OFF)
        assert valid is True
        assert state is not None
        assert state.raw == FRAME_500D_OFF

    def test_invalid_frame_keeps_previous_state(self) -> None:
        """As in he.updateData, a DATA-ERROR frame keeps the old decoding."""
        previous = decode(FRAME_500D_OFF, "cvp")
        state, valid = decode_device_data("cvp", "999999", previous=previous)
        assert (state, valid) == (previous, False)

    def test_rvu_is_not_decoded(self) -> None:
        """RVU frames are only validated."""
        assert decode_device_data("rvu", "5400" + "0000" * 23) == (None, True)
        assert decode_device_data("rvu", "999999") == (None, False)
