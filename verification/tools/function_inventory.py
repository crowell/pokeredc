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
import tomllib
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


def _port_index(root: Path) -> dict[str, dict[str, object]]:
    """Return the current C-port status indexed by assembly entry symbol."""
    catalog = tomllib.loads((root / "verification/ports.toml").read_text())
    return {
        str(entry["assembly_symbol"]): entry
        for entry in catalog.get("function", [])
    }


# This is the narrow execution path from a cold boot to the first frame where
# the player can control Red.  It is deliberately hand-curated: static call
# graph candidates alone cannot distinguish the title/menu state machines from
# a leaf routine shared by an unrelated battle path.
BOOT_TO_OVERWORLD = (
    "PlayIntro",
    "PrepareTitleScreen",
    "DisplayTitleScreen",
    "TitleScreenPickNewMon",
    "TitleScreenAnimateBallIfStarterOut",
    "MainMenu",
    "OakSpeech",
    "AddItemToInventory",
    "PrepareForSpecialWarp",
    "ChoosePlayerName",
    "ChooseRivalName",
    "AskName",
    "DisplayNamingScreen",
    "LoadEDTile",
    "PrintAlphabet",
    "PrintNicknameAndUnderscores",
    "DakutensAndHandakutens",
    "PrintNamingText",
    "SpecialEnterMap",
    "EnterMap",
    "LoadMapData",
    "InitMapSprites",
    "LoadMapSpriteTilePatterns",
    "LoadPlayerSpriteGraphics",
    "CheckForceBikeOrSurf",
    "OverworldLoop",
    "OverworldLoopLessDelay",
    "JoypadOverworld",
    "RunMapScript",
    "UpdatePlayerSprite",
    "UpdateNPCSprite",
    "CanWalkOntoTile",
    "CollisionCheckOnLand",
    "CollisionCheckOnWater",
    "CheckWarpsNoCollision",
    "CheckWarpsCollision",
    "WarpFound2",
    "CheckMapConnections",
    "DisplayTextID",
)


def _backlog_markdown(root: Path, labels: dict[str, Label]) -> str:
    """Render the actionable C-port backlog from the live port catalog.

    A function is *missing* when a static assembly call/jump candidate has no
    ports.toml entry.  A function is *partial* when it has a C entry but is not
    marked proven.  Proven entries are intentionally omitted from the task
    list, so agents do not repeat completed work.
    """
    records = _records(labels)
    ports = _port_index(root)
    by_name = {str(record["name"]): record for record in records}
    missing = [record for record in records if str(record["name"]) not in ports]
    partial = [
        record for record in records
        if str(record["name"]) in ports
        and str(ports[str(record["name"])].get("status", "")) != "proven"
    ]
    proven = len(records) - len(missing) - len(partial)

    lines = [
        "# C Porting Backlog",
        "",
        "Generated by `verification/tools/function_inventory.py --backlog "
        "--output verification/PORTING_BACKLOG.md`.",
        "",
        "This is a conservative static-call-graph backlog, not a claim that "
        "every label is a clean C ABI boundary. Each item is either missing "
        "from `ports.toml` or has an existing port marked `partial`.",
        "",
        "## Snapshot",
        "",
        f"- Static call/jump candidates: {len(records)}",
        f"- Proven catalog entries excluded: {proven}",
        f"- Existing partial ports to complete: {len(partial)}",
        f"- Missing C ports: {len(missing)}",
        "",
        "## Runtime prerequisite",
        "",
        "Before composing these functions into the macOS game, replace the "
        "current flat 64 KiB proof-memory ROM model with bank-aware reads and "
        "writes (including MBC1 ROM/RAM banking). Several ports switch "
        "`hLoadedROMBank`/`rROMB` internally; remapping only between C calls "
        "cannot execute the real control flow correctly.",
        "",
        "## Boot-to-overworld critical path",
        "",
        "Complete the non-proven entries in this dependency order to boot, "
        "finish the opening flow, load Red's initial map, and run the first "
        "interactive overworld frame.",
        "",
        "| Function | Current status | Assembly source |",
        "| --- | --- | --- |",
    ]
    for name in BOOT_TO_OVERWORLD:
        record = by_name.get(name)
        if record is None:
            continue
        port = ports.get(name)
        status = "missing" if port is None else str(port.get("status", "unknown"))
        lines.append(
            f"| `{name}` | {status} | `{record['path']}:{record['line']}` |"
        )

    def emit_group(title: str, items: list[dict[str, object]]) -> None:
        lines.extend(["", f"## {title}", ""])
        if not items:
            lines.append("None.")
            return
        current_path: str | None = None
        for record in items:
            path = str(record["path"])
            if path != current_path:
                current_path = path
                lines.extend(["", f"### `{path}`", ""])
            callers = ", ".join(f"`{caller}`" for caller in record["callers"])
            if not callers:
                callers = "static entry/jump only"
            status = "missing"
            source = ""
            port = ports.get(str(record["name"]))
            if port is not None:
                status = str(port.get("status", "unknown"))
                source = f" — `{port.get('c_source', '')}`"
            lines.append(
                f"- `{record['name']}` — assembly line {record['line']}; "
                f"callers: {callers}; status: **{status}**{source}"
            )

    emit_group("Partial ports to complete", partial)
    emit_group("Missing C ports", missing)
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--json", action="store_true", help="emit candidate records as JSON")
    parser.add_argument(
        "--backlog",
        action="store_true",
        help="emit the actionable missing/partial C-port backlog as Markdown",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="write --backlog output to this path (relative to --root if needed)",
    )
    args = parser.parse_args()

    if args.json and args.backlog:
        parser.error("--json and --backlog are mutually exclusive")
    if args.output is not None and not args.backlog:
        parser.error("--output requires --backlog")

    root = args.root.resolve()
    labels = build_inventory(root)
    records = _records(labels)
    if args.json:
        print(json.dumps(records, indent=2))
        return 0
    if args.backlog:
        output = _backlog_markdown(root, labels)
        if args.output is None:
            print(output)
        else:
            path = args.output if args.output.is_absolute() else root / args.output
            path.write_text(output)
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
