from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

import claripy


class ConstrainedEndpoint(Protocol):
    constraints: tuple[claripy.ast.Bool, ...]


def assert_pathwise_equivalent(
    assembly: Sequence[ConstrainedEndpoint],
    native: Sequence[ConstrainedEndpoint],
    observables: Sequence[str],
) -> None:
    """Prove equality over every overlapping pair of terminal path domains."""

    if not assembly or not native:
        raise AssertionError("both programs must have terminal paths")

    overlaps: list[tuple[int, int]] = []
    for assembly_index, assembly_end in enumerate(assembly):
        for native_index, native_end in enumerate(native):
            solver = claripy.Solver()
            solver.add(assembly_end.constraints)
            solver.add(native_end.constraints)
            if not solver.satisfiable():
                continue

            overlaps.append((assembly_index, native_index))
            differences = [
                getattr(assembly_end, name) != getattr(native_end, name)
                for name in observables
            ]
            solver.add(claripy.Or(*differences))
            if solver.satisfiable():
                model = {
                    name: (
                        solver.eval(getattr(assembly_end, name), 1)[0],
                        solver.eval(getattr(native_end, name), 1)[0],
                    )
                    for name in observables
                }
                raise AssertionError(f"observable mismatch: {model}")

    if {left for left, _ in overlaps} != set(range(len(assembly))):
        raise AssertionError("an assembly terminal path has no native overlap")
    if {right for _, right in overlaps} != set(range(len(native))):
        raise AssertionError("a native terminal path has no assembly overlap")
