from __future__ import annotations

from pathlib import Path

import pytest
from pypcode import Context

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_subtract_amount_paid_from_money__uses_z80_compatible_instruction_encodings() -> None:
    location = symbol_location(SYMBOLS, "SubtractAmountPaidFromMoney_")
    instructions = Context("z80:LE:16:default").disassemble(
        linked_bytes(ROM, location, 35), location.address
    ).instructions
    body = [(item.mnem, item.body, item.length) for item in instructions]
    assert ("CALL", "0x3a8e", 3) in body  # StringCmp
    assert ("RET", "C", 1) in body  # ret c
    assert ("CALL", "0x3e6d", 3) in body  # Predef (SubBCDPredef)
    assert ("AND", "A", 1) in body
