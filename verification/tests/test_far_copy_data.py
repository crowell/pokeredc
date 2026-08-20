from __future__ import annotations

from verification.tests import test_far_copy_data_equivalence as far_copy


def test_far_copy_data_pathwise_equivalence() -> None:
    far_copy.test_transition_equivalence()
