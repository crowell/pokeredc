from __future__ import annotations

import pytest

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.tests import test_random_equivalence as random_equivalence


@pytest.mark.skipif(
    not random_equivalence.ROM.exists() or not random_equivalence.SYMS.exists(),
    reason="run `make red`",
)
@pytest.mark.skipif(not random_equivalence.ELF.exists(), reason="run native")
def test_random_pathwise_equivalence() -> None:
    inputs = random_equivalence.inputs("random_compat")
    assert_pathwise_equivalent(
        random_equivalence.assembly(inputs),
        random_equivalence.native(inputs),
        random_equivalence.OBSERVABLES,
    )
