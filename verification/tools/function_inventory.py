#!/usr/bin/env python3
"""Build a conservative inventory of assembly function candidates.

RGBDS labels describe code, data, aliases, and bytecode entry points alike.
This tool therefore reports *candidates* based on exported labels and static
control-transfer targets; it does not pretend that every global label is a C
function boundary.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


LABEL_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_#@]*)(:{1,2})(?:\s*;.*)?$")
TRANSFER_RE = re.compile(
    r"^\s*(call|jp|farcall|callfar|farjp|jpfar|homecall|homecall_sf|predef|predef_jump)\s+(.+?)\s*$",
    re.IGNORECASE,
)
DIRECT_CALLS = {"call", "farcall", "callfar", "homecall", "homecall_sf", "predef"}
DIRECT_JUMPS = {"jp", "farjp", "jpfar", "predef_jump"}
CANDIDATE_REASONS = {"direct_call", "direct_jump"}
CONDITIONS = {"z", "nz", "c", "nc"}


@dataclass
class Label:
    name: str
    path: str
    line: int
    exported: bool
    reasons: set[str] = field(default_factory=set)
    callers: set[str] = field(default_factory=set)
    callees: set[str] = field(default_factory=set)


def _source_files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*.asm")
        if ".git" not in path.parts and "verification" not in path.parts
    )


def _target(operand_text: str) -> str | None:
    operand = operand_text.split(";", 1)[0].strip()
    pieces = [piece.strip() for piece in operand.split(",")]
    if len(pieces) == 2 and pieces[0].lower() in CONDITIONS:
        operand = pieces[1]
    elif len(pieces) != 1:
        return None

    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_#@]*", operand):
        return operand
    return None


def build_inventory(root: Path) -> dict[str, Label]:
    files = _source_files(root)
    labels: dict[str, Label] = {}

    for path in files:
        relative = str(path.relative_to(root))
        for line_number, raw_line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            match = LABEL_RE.match(raw_line.strip())
            if match and match.group(1) not in labels:
                labels[match.group(1)] = Label(
                    name=match.group(1),
                    path=relative,
                    line=line_number,
                    exported=match.group(2) == "::",
                )

    for label in labels.values():
        if label.exported:
            label.reasons.add("exported")

    for path in files:
        current_label: str | None = None
        for raw_line in path.read_text(errors="replace").splitlines():
            stripped = raw_line.strip()
            label_match = LABEL_RE.match(stripped)
            if label_match:
                current_label = label_match.group(1)
                continue

            transfer_match = TRANSFER_RE.match(stripped)
            if not transfer_match:
                continue
            operation = transfer_match.group(1).lower()
            target = _target(transfer_match.group(2))
            if target is None or target not in labels:
                continue

            reason = "direct_call" if operation in DIRECT_CALLS else "direct_jump"
            labels[target].reasons.add(reason)
            if current_label is not None and current_label in labels:
                labels[target].callers.add(current_label)
                labels[current_label].callees.add(target)

    return labels


def _records(labels: dict[str, Label]) -> list[dict[str, object]]:
    # Exported RGBDS symbols include large amounts of data. An exported-only
    # label is useful metadata, but is not a function candidate until a static
    # code transfer targets it (or a future manual entry-point list adds it).
    candidates = [
        label for label in labels.values() if label.reasons.intersection(CANDIDATE_REASONS)
    ]
    return [
        {
            "name": label.name,
            "path": label.path,
            "line": label.line,
            "reasons": sorted(label.reasons),
            "callers": sorted(label.callers),
            "callees": sorted(label.callees),
            "leaf": not label.callees,
        }
        for label in sorted(candidates, key=lambda item: (item.path, item.line, item.name))
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--json", action="store_true", help="emit candidate records as JSON")
    args = parser.parse_args()

    labels = build_inventory(args.root.resolve())
    records = _records(labels)
    if args.json:
        print(json.dumps(records, indent=2))
        return 0

    reasons: dict[str, int] = defaultdict(int)
    for record in records:
        for reason in record["reasons"]:
            reasons[str(reason)] += 1

    print(f"global labels: {len(labels)}")
    print(f"exported labels: {sum(label.exported for label in labels.values())}")
    print(f"function candidates: {len(records)}")
    print(f"leaf candidates: {sum(bool(record['leaf']) for record in records)}")
    for reason, count in sorted(reasons.items()):
        print(f"{reason}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
