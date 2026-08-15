from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "afeac7cfea83d03deaeec0cdb123cdaf200e08fa5cd0a728043eea181dfa59d0fec83814fef3280cfef720043eea180a3eed18063ef318023ef0c3a123"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_play_battle_music_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "PlayBattleMusic")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY