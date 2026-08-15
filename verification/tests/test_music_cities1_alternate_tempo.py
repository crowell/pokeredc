from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "3e0aeac8cfeac9cf3effeac7cf0e64cd39370e023ec3cda1232106c0116f6ac3605b"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_music_cities1_alternate_tempo_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "Music_Cities1AlternateTempo")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY