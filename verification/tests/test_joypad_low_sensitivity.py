from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "cd9a01f0b7a7f0b32802f0b4e0b5f0b3a728053e1ee0d5c9f0d5a72804afe0b5c9f0b4e6032808f0b6a72003afe0b53e05e0d5c9"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_joypad_low_sensitivity_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "JoypadLowSensitivity")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY