# Copyright (c) 2026 Edoardo Mistretta

"""Builder of fancoil lastData frames for the tests."""

FLAG_ON = 1 << 0
FLAG_REQUEST = 1 << 1
FLAG_AUTO = 1 << 2
FLAG_NIGHT = 1 << 7
FLAG_REMOTE = 1 << 8  # 1 = remote NOT active, except on 500B/500C
FLAG_TIMER = 1 << 12
FLAG_SABIANET = 1 << 13
FLAG_WINDOW = 1 << 14
FLAGS_ON = FLAG_ON | FLAG_REMOTE


def build_frame(  # noqa: PLR0913
    *,
    model: str = "500D",
    fan: int = 4,
    mode: int = 1,
    flags: int = FLAGS_ON,
    flap: int = 0x0000,
    t1: int = 225,
    setpoint_summer: int = 240,
    setpoint_winter: int = 200,
    setpoint_auto: int = 220,
    range_summer: int = 0xC800,
    range_winter: int = 0xC800,
    alarms: int = 0,
    clock: int = 0x467B,
    fw_esp: int = 0x002B,
    dip: int = 0,
    words: int = 20,
) -> str:
    """Build a fancoil frame, one keyword per word (values are 16-bit)."""
    values = [
        int(model, 16),
        0x002B,
        (fan << 8) | mode,
        flags,
        flap,
        t1,
        setpoint_summer,
        setpoint_winter,
        setpoint_auto,
        range_summer,
        range_winter,
        0,
        alarms,
        clock,
        fw_esp,
        0,
        dip,
    ]
    values += [0] * (words - len(values))
    return "".join(f"{v & 0xFFFF:04x}" for v in values[:words])
