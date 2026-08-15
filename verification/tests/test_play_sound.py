from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "e5d5c547faeec0a7280dafea2ac0ea2bc0ea2cc0ea2dc0fac7cfa72815faeec0a72851afeaeec0facacffeff2035afeac7cfafeaeec0f0b8e0b9faefc0e0b8ea0020fe02200678cd7658180efe08200678cd3560180478cdea58f0b9e0b8ea0020181178eacacffac7cfeac8cfeac9cf78eac7cfc1d1e1c9facbcf3dc0f0b8f53e01e0b8ea0020cd344cf1e0b8ea0020c9fe04040b0f"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_play_sound_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "PlaySound")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY