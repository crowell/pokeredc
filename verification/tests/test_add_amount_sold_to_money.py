from __future__ import annotations

from pathlib import Path

import claripy
import pytest

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.tests import test_add_amount_sold_to_money_equivalence as add_amount

ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"


@pytest.mark.skipif(not add_amount.NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_add_amount_sold_to_money_pathwise_equivalence() -> None:
    values = add_amount.symbolic_registers("add_amount_compat")
    for field in add_amount.FIELDS:
        values[field] = claripy.BVS(f"add_amount_compat_{field}", 8)
    values["sound_f"] = claripy.Concat(
        claripy.BVS("add_amount_compat_sound_flags", 4), claripy.BVV(0, 4)
    )
    assert_pathwise_equivalent(
        add_amount._assembly(values),
        add_amount._native(values),
        ("a", "f", "b", "c", "d", "e", "h", "l", *add_amount.FIELDS),
    )
