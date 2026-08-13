from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

import angr
import claripy


@dataclass(frozen=True)
class SymbolLocation:
    bank: int
    address: int


def symbol_location(path: Path, name: str) -> SymbolLocation:
    for raw_line in path.read_text().splitlines():
        line = raw_line.split(";", 1)[0].strip()
        if not line:
            continue
        encoded_address, symbol = line.split(maxsplit=1)
        if symbol == name:
            bank, address = encoded_address.split(":", 1)
            return SymbolLocation(int(bank, 16), int(address, 16))
    raise KeyError(f"symbol not found: {name}")


def rom_window(path: Path, bank: int) -> BytesIO:
    """Return the logical 0000-7fff ROM view for one cartridge bank."""

    rom = path.read_bytes()
    fixed = rom[:0x4000]
    if bank == 0:
        return BytesIO(fixed)

    start = bank * 0x4000
    switchable = rom[start : start + 0x4000]
    if len(switchable) != 0x4000:
        raise ValueError(f"ROM bank {bank:#x} is absent or truncated")
    return BytesIO(fixed + switchable)


def linked_bytes(path: Path, location: SymbolLocation, size: int) -> bytes:
    """Read bytes at a banked RGBDS symbol location from the physical ROM."""

    if location.address < 0x4000:
        offset = location.address
    else:
        offset = location.bank * 0x4000 + location.address - 0x4000
    data = path.read_bytes()[offset : offset + size]
    if len(data) != size:
        raise ValueError(f"short ROM read at {location}")
    return data


def z80_flags_to_sm83(z80_f: claripy.ast.BV) -> claripy.ast.BV:
    """Map Z80 Z/N/H/C flags into canonical SM83 flag positions."""

    # Z80: S Z Y H X P/V N C; SM83: Z N H C 0 0 0 0.
    return claripy.Concat(
        z80_f[6], z80_f[1], z80_f[4], z80_f[0], claripy.BVV(0, 4)
    )


def sm83_flags_to_z80(sm83_f: claripy.ast.BV) -> claripy.ast.BV:
    """Map canonical SM83 Z/N/H/C bits into their Z80 positions."""

    return (
        claripy.ZeroExt(7, sm83_f[7]) << 6
        | claripy.ZeroExt(7, sm83_f[6]) << 1
        | claripy.ZeroExt(7, sm83_f[5]) << 4
        | claripy.ZeroExt(7, sm83_f[4])
    )


def collect_returns(
    project: angr.Project, state: angr.SimState, return_address: int
) -> list[angr.SimState]:
    """Execute all paths and collect states before the return sentinel runs."""

    manager = project.factory.simulation_manager(state)
    manager.stashes["returned"] = []
    while manager.active:
        manager.move(
            from_stash="active",
            to_stash="returned",
            filter_func=lambda candidate: candidate.addr == return_address,
        )
        if manager.active:
            manager.step()
    if manager.errored:
        raise AssertionError(manager.errored)
    if not manager.returned:
        raise AssertionError("no path reached the return sentinel")
    return manager.returned
