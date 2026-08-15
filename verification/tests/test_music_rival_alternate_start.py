from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "0e023edecda1232106c011a271cd605b111d72cd605b11b572"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_music_rival_alternate_start_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "Music_RivalAlternateStart")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY