from __future__ import annotations

import pytest

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS
from verification.tests import test_remove_inventory as remove_inventory


@pytest.mark.skipif(not remove_inventory.NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not remove_inventory.ROM.exists() or not remove_inventory.SYMBOLS.exists(),
    reason="run red",
)
def test_remove_item_from_inventory_pathwise_equivalence() -> None:
    cases = (
        (remove_inventory.assembly_begin, "begin", "begin"),
        (remove_inventory.assembly_step, "step", "step"),
        (remove_inventory.assembly_finish, "finish", "finish"),
    )
    for assembly, name, kind in cases:
        values = remove_inventory.inputs(f"remove_item_{name}")
        assert_pathwise_equivalent(
            assembly(values),
            remove_inventory.native(
                "port_remove_item_from_inventory_" + kind, values, kind
            ),
            (*REGISTERS, "memory", "continuation"),
        )
