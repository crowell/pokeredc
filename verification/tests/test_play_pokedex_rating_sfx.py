from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "f0dc0e00217051be38040c2318f9c53effeaeec0cd4037c1060021625109092a4ecda123c30723"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_play_pokedex_rating_sfx_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "PlayPokedexRatingSfx")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY