from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "0168010421a0c33e7f220d20fc0520f9c3d73de53e79223ccd4f193c77e1"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_clear_screen_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "ClearScreen")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY