from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "f08bf5f08cf5afe08b3e06e08ce5fa9bd0a72803cdc65621f2c4cd043ce1cd31383e2dcd6d3ef0b5e60328e1f1e08cf1e08bc9"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_wait_for_text_scroll_button_press_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "WaitForTextScrollButtonPress")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY