"""Bank-aware proof memory: MBC1 ROM/RAM banking with window sync.

The historical flat model mapped one 32 KiB ``rom_window`` at 0x0000-0x7FFF
and never changed it when code wrote rROMB (0x2000) or hLoadedROMBank
(0xFFB8) mid-function, so ports that switch banks internally read stale
window bytes after the switch. This module re-syncs the 0x4000-0x7FFF
window from the full ROM image on every MBC1 / hLoadedROMBank write, plus
an 8 KiB SRAM window at 0xA000-0xBFFF with 4 RAM banks.

Address-size constraint: assembly states run under the 16-bit
``z80:LE:16:default`` backend, so any in-state offset past 0xFFFF wraps
and would corrupt GameBoy memory. The backing images therefore live
Python-side (closure bytes plus ``state.globals`` shadow/SRAM dicts) for
assembly states, while native x86-64 states additionally mirror the
``verification/include/bank.h`` in-state layout (ROM backing at +0x20000,
shadow at +0x1F000, SRAM backing at +0x120000) used by the C helpers.
Equivalence only ever observes real GameBoy addresses (window bytes, bank
registers), where both sides agree exactly.
"""

from __future__ import annotations

from pathlib import Path

ROM_WINDOW_BASE = 0x4000
ROM_WINDOW_SIZE = 0x4000
ROM_BANK_COUNT = 64
ROM_BACKING_BASE = 0x20000
MBC_STATE_BASE = 0x1F000
SRAM_WINDOW_BASE = 0xA000
SRAM_WINDOW_SIZE = 0x2000
SRAM_BANK_COUNT = 4
SRAM_BACKING_BASE = 0x120000

H_LOADED_ROM_BANK = 0xFFB8
R_ROMB = 0x2000

MBC_RAM_ENABLE_OFF = 0
MBC_ROM_LOW5_OFF = 1
MBC_RAM_HIGH2_OFF = 2
MBC_MODE_OFF = 3
MBC_RAM_BANK_OFF = 4


def effective_bank(raw: int) -> int:
    """MBC1 low-5 adjustment: bank 0 in the low bits means bank 1."""
    low = raw & 0x1F
    if low == 0:
        low = 1
    return (raw & 0x60) | low


def read_rom_banks(rom_path: Path, count: int = ROM_BANK_COUNT) -> bytes:
    """Return the first ``count`` 16 KiB ROM banks concatenated."""
    data = rom_path.read_bytes()
    want = count * ROM_WINDOW_SIZE
    if len(data) < want:
        raise ValueError(f"ROM image is {len(data)} bytes, need {want}")
    return data[:want]


def _bank_slice(image: bytes, bank: int) -> bytes:
    start = (bank % ROM_BANK_COUNT) * ROM_WINDOW_SIZE
    return image[start : start + ROM_WINDOW_SIZE]

def install_mbc1(state, base: int, rom_path: Path, hook_writes: bool = True,
                 banks: tuple = (1,)):
    """Map bank 1 into the window and install MBC1 write hooks.

    ``base`` is 0 for assembly states, NATIVE_MEMORY for native states.
    Native states also receive the in-state backing slices for ``banks``
    plus the shadow layout that ``bank.h`` helpers use (safe: x86-64
    addresses); pass every bank the C code will select (bank 1 is the
    entry window). Assembly states keep backing Python-side (16-bit
    addresses would wrap) and get identical window bytes through the
    hooks. ``hook_writes=False`` skips hook installation (native C
    already copies the window itself; its copy loops must not be
    reinterpreted as MBC control writes).

    Returns the ROM image bytes (for direct assertions).
    """
    image = read_rom_banks(rom_path)
    native_backing = base != 0
    guard_key = f"mbc1_guard_{base:#x}"
    shadow_key = f"mbc1_shadow_{base:#x}"
    sram_key = f"mbc1_sram_{base:#x}"

    state.globals[shadow_key] = {"ram_enable": 0, "low5": 1, "high2": 0, "mode": 0}
    state.globals[sram_key] = {
        "ram_bank": 0,
        "backing": [bytearray(SRAM_WINDOW_SIZE) for _ in range(SRAM_BANK_COUNT)],
    }
    state.memory.store(base + ROM_WINDOW_BASE, _bank_slice(image, 1))
    state.memory.store(base + H_LOADED_ROM_BANK, bytes((1,)))
    state.memory.store(base + R_ROMB, bytes((1,)))
    if native_backing:
        # x86-64 only: in-state slices for the bank.h C helpers.
        for bank in dict.fromkeys((1,) + tuple(banks)):
            if 0 <= bank < ROM_BANK_COUNT:
                state.memory.store(
                    base + ROM_BACKING_BASE + bank * ROM_WINDOW_SIZE,
                    _bank_slice(image, bank),
                )
    if native_backing:
        state.memory.store(
            base + SRAM_BACKING_BASE, bytes(SRAM_WINDOW_SIZE * SRAM_BANK_COUNT)
        )
        state.memory.store(
            base + MBC_STATE_BASE + MBC_RAM_ENABLE_OFF, bytes((0, 1, 0, 0, 0))
        )

    def _shadow(current):
        shadow = current.globals.get(shadow_key)
        if shadow is None:
            shadow = {"ram_enable": 0, "low5": 1, "high2": 0, "mode": 0}
            current.globals[shadow_key] = shadow
        return shadow

    def _sram(current):
        sram = current.globals.get(sram_key)
        if sram is None:
            sram = {
                "ram_bank": 0,
                "backing": [bytearray(SRAM_WINDOW_SIZE) for _ in range(SRAM_BANK_COUNT)],
            }
            current.globals[sram_key] = sram
        return sram

    def _in_hook(current) -> bool:
        return bool(current.globals.get(guard_key, False))

    def _copy_rom(current, bank: int) -> None:
        current.globals[guard_key] = True
        try:
            current.memory.store(base + ROM_WINDOW_BASE, _bank_slice(image, bank & 0x7F))
        finally:
            current.globals[guard_key] = False

    def _mirror_bank(current, bank: int) -> None:
        current.globals[guard_key] = True
        try:
            current.memory.store(base + H_LOADED_ROM_BANK, bank, size=1)
            current.memory.store(base + R_ROMB, bank, size=1)
        finally:
            current.globals[guard_key] = False

    def _copy_sram_bank(current, ram_bank: int) -> None:
        sram = _sram(current)
        current.globals[guard_key] = True
        try:
            current.memory.store(
                base + SRAM_WINDOW_BASE, bytes(sram["backing"][ram_bank & 0x03])
            )
        finally:
            current.globals[guard_key] = False

    def _flush_sram_window(current) -> None:
        sram = _sram(current)
        current.globals[guard_key] = True
        try:
            data = current.memory.load(base + SRAM_WINDOW_BASE, SRAM_WINDOW_SIZE)
            try:
                raw = current.solver.eval_one(data, cast_to=bytes)
            except Exception:
                return
            sram["backing"][sram["ram_bank"] & 0x03][:] = raw
        finally:
            current.globals[guard_key] = False

    def on_write(current) -> None:
        state = current
        if _in_hook(state):
            return
        addr = state.inspect.mem_write_address
        expr = state.inspect.mem_write_expr
        if addr is None or expr is None:
            return
        try:
            concrete_addr = state.solver.eval_one(addr)
        except Exception:
            return
        if base == 0 and concrete_addr >= 0x10000:
            return
        local = concrete_addr - base if base else concrete_addr
        if local == H_LOADED_ROM_BANK:
            try:
                raw = state.solver.eval_one(expr)
            except Exception:
                return
            bank = effective_bank(raw & 0xFF)
            _shadow(state)["low5"] = bank & 0x1F
            _mirror_bank(state, bank)
            _copy_rom(state, bank)
        elif 0x2000 <= local < 0x4000:
            try:
                size = state.inspect.mem_write_length
                length = state.solver.eval_one(size) if size is not None else 1
            except Exception:
                length = 1
            if length != 1:
                return
            try:
                raw = state.solver.eval_one(expr)
            except Exception:
                return
            shadow = _shadow(state)
            low = raw & 0x1F
            if low == 0:
                low = 1
            shadow["low5"] = low
            bank = low | ((shadow["high2"] & 0x03) << 5)
            _mirror_bank(state, bank)
            _copy_rom(state, bank)
        elif 0x0000 <= local < 0x2000:
            try:
                raw = state.solver.eval_one(expr)
            except Exception:
                return
            _shadow(state)["ram_enable"] = 1 if (raw & 0x0F) == 0x0A else 0
        elif 0x4000 <= local < 0x6000:
            try:
                raw = state.solver.eval_one(expr)
            except Exception:
                return
            shadow = _shadow(state)
            if shadow["mode"] != 0:
                _flush_sram_window(state)
                _sram(state)["ram_bank"] = raw & 0x03
                _copy_sram_bank(state, raw & 0x03)
            else:
                shadow["high2"] = raw & 0x03
                bank = shadow["low5"] | ((raw & 0x03) << 5)
                _mirror_bank(state, bank)
                _copy_rom(state, bank)
        elif 0x6000 <= local < 0x8000:
            try:
                raw = state.solver.eval_one(expr)
            except Exception:
                return
            _shadow(state)["mode"] = raw & 0x01

    if hook_writes:
        state.inspect.b("mem_write", when="before", action=on_write)
    return image
