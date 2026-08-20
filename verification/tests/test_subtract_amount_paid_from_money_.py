from __future__ import annotations

import claripy
import pytest

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.tests import test_subtract_amount_paid_from_money as subtract_paid


@pytest.mark.skipif(not subtract_paid.NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not subtract_paid.ROM.exists() or not subtract_paid.SYMBOLS.exists(),
    reason="run red",
)
def test_subtract_amount_paid_from_money_pathwise_equivalence() -> None:
    values = subtract_paid.symbolic_registers("subtract_paid_compat")
    for field in subtract_paid.FIELDS:
        values[field] = claripy.BVS(f"subtract_paid_compat_{field}", 8)
    assert_pathwise_equivalent(
        subtract_paid._assembly(values),
        subtract_paid._native(values),
        ("a", "f", *subtract_paid.FIELDS),
    )
