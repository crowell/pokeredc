from __future__ import annotations

import pytest

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.tests import test_joypad_equivalence as joypad


@pytest.mark.skipif(not joypad.NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not joypad.ROM.exists() or not joypad.SYMBOLS.exists(),
    reason="run `make red`",
)
def test_joypad_pathwise_equivalence() -> None:
    assert_pathwise_equivalent(
        joypad._assembly_endpoints(),
        joypad._native_endpoints(),
        (
            "hJoyInput",
            "hJoyLast",
            "hJoyReleased",
            "hJoyPressed",
            "hJoyHeld",
            "wStatusFlags5",
            "wJoyIgnore",
        ),
    )
