from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "3e9acd4037210ec0112263cd1d63112563cd1d63119b44"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_music_poke_flute_in_battle_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "Music_PokeFluteInBattle")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY