from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "11df641afeffc8ea91cf131aea27d113cd273918ee0a5a1514683876384a39ff"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_set_debug_new_game_party_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "SetDebugNewGameParty")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY