from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "f0b8f5fa94cffe013e0120023e0fe0b8ea0020218fcf2a666ffa91cffec43013"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_get_item_price_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "GetItemPrice")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY