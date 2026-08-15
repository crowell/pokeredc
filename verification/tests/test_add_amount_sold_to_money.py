from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "1149d321a1ff0e033e0bcd6d3e3e13ea25d1cde8303eb2cd4037c34837f0b8f53e03e0b8ea0020cd"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_add_amount_sold_to_money_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "AddAmountSoldToMoney")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY