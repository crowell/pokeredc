from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "3e02eaefc0eaf0c0afeac7cfeaeec0eacacf3dc3"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_stop_all_sounds_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "StopAllSounds")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY