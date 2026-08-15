from __future__ import annotations

from pathlib import Path

import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

EXPECTED_BODY = bytes.fromhex(
    "060121216bc3d6351149d321a1ff0e033e0bcd6d"
)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_subtract_amount_paid_from_money_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "SubtractAmountPaidFromMoney")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY