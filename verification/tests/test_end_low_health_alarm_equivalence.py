from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    native_registers,
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import (
    linked_bytes,
    rom_window,
    symbol_location,
    z80_flags_to_sm83,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF

# Memory addresses from asm
W_LOW_HEALTH_ALARM = 0xD89C
W_CHANNEL_SOUND_IDS_CHAN5 = 0xC02A
W_LOW_HEALTH_ALARM_DISABLED = 0xCCF6
W_PLAYER_NUM_ATTACKS_LEFT = 0xD06A
W_ENEMY_NUM_ATTACKS_LEFT = 0xD06F
W_PLAYER_BATTLE_STATUS1 = 0xD062
W_ENEMY_BATTLE_STATUS1 = 0xD067
USING_TRAPPING_MOVE_BIT = 4
USING_TRAPPING_MOVE_MASK = 1 << USING_TRAPPING_MOVE_BIT  # 0x10


@dataclass(frozen=True)
class E:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class EndLowHealthAlarm(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        # EndLowHealthAlarm:
        #   xor a
        #   ld [wLowHealthAlarm], a        ; wLowHealthAlarm = 0
        #   ld [wChannelSoundIDs + CHAN5], a  ; wChannelSoundIDs+CHAN5 = 0
        #   inc a                          ; a = 1
        #   ld [wLowHealthAlarmDisabled], a  ; wLowHealthAlarmDisabled = 1
        #   ret
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)  # Z flag (Z=1)
        self.state.memory.store(W_LOW_HEALTH_ALARM, claripy.BVV(0, 8))
        self.state.memory.store(W_CHANNEL_SOUND_IDS_CHAN5, claripy.BVV(0, 8))
        self.state.regs.a = claripy.BVV(1, 8)
        self.state.regs.f = claripy.BVV(0x00, 8)  # inc a clears Z
        self.state.memory.store(W_LOW_HEALTH_ALARM_DISABLED, claripy.BVV(1, 8))
        self.jump(self._n)


class CheckNumAttacksLeft(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        # CheckNumAttacksLeft:
        #   ld a, [wPlayerNumAttacksLeft]
        #   and a
        #   jr nz, .checkEnemy
        #   ; player has 0 attacks left
        #   ld hl, wPlayerBattleStatus1
        #   res USING_TRAPPING_MOVE, [hl]
        # .checkEnemy:
        #   ld a, [wEnemyNumAttacksLeft]
        #   and a
        #   ret nz
        #   ; enemy has 0 attacks left
        #   ld hl, wEnemyBattleStatus1
        #   res USING_TRAPPING_MOVE, [hl]
        #   ret

        # Read player attacks
        player_attacks = self.state.memory.load(W_PLAYER_NUM_ATTACKS_LEFT, 1)
        # Read enemy attacks
        enemy_attacks = self.state.memory.load(W_ENEMY_NUM_ATTACKS_LEFT, 1)

        # Read current status flags
        player_status1 = self.state.memory.load(W_PLAYER_BATTLE_STATUS1, 1)
        enemy_status1 = self.state.memory.load(W_ENEMY_BATTLE_STATUS1, 1)

        # For player: if attacks == 0, clear USING_TRAPPING_MOVE bit
        player_status1_new = claripy.If(
            player_attacks == 0,
            player_status1 & ~USING_TRAPPING_MOVE_MASK,
            player_status1
        )
        self.state.memory.store(W_PLAYER_BATTLE_STATUS1, player_status1_new)

        # For enemy: if attacks == 0, clear USING_TRAPPING_MOVE bit
        enemy_status1_new = claripy.If(
            enemy_attacks == 0,
            enemy_status1 & ~USING_TRAPPING_MOVE_MASK,
            enemy_status1
        )
        self.state.memory.store(W_ENEMY_BATTLE_STATUS1, enemy_status1_new)

        # Z80 flags: AND a sets Z if a==0, H=1, N=0, C=0
        # For the final enemy check
        z = claripy.If(enemy_attacks == 0, claripy.BVV(0x40, 8), claripy.BVV(0x00, 8))
        h = claripy.BVV(0x10, 8)
        f = z | claripy.BVV(0x10, 8)  # H=1 always for AND, Z if enemy_attacks==0

        self.state.regs.a = enemy_attacks
        self.state.regs.f = f
        # The asm leaves hl pointing to the last accessed status byte
        # The native C doesn't modify h/l - leave them as-is (from inputs)
        self.jump(self._n)


def inputs(p: str) -> dict:
    i = symbolic_registers(p)
    i["player_attacks"] = claripy.BVS(f"{p}_pa", 8)
    i["enemy_attacks"] = claripy.BVS(f"{p}_ea", 8)
    i["player_status1"] = claripy.BVS(f"{p}_ps1", 8)
    i["enemy_status1"] = claripy.BVS(f"{p}_es1", 8)
    return i


def assembly(i: dict, asm_symbol: str) -> list:
    loc = symbol_location(SYMBOLS, asm_symbol)
    q = loc.address
    p = angr.Project(
        rom_window(ROM, loc.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": q,
        },
    )
    if asm_symbol == "EndLowHealthAlarm":
        p.hook(q, EndLowHealthAlarm(DONE), length=12)
    else:
        p.hook(q, CheckNumAttacksLeft(DONE), length=20)
    s = p.factory.blank_state(addr=q)
    # Store initial memory values
    s.memory.store(W_LOW_HEALTH_ALARM, claripy.BVV(0xFF, 8))
    s.memory.store(W_CHANNEL_SOUND_IDS_CHAN5, claripy.BVV(0xAA, 8))
    s.memory.store(W_LOW_HEALTH_ALARM_DISABLED, claripy.BVV(0x00, 8))
    s.memory.store(W_PLAYER_NUM_ATTACKS_LEFT, i["player_attacks"])
    s.memory.store(W_ENEMY_NUM_ATTACKS_LEFT, i["enemy_attacks"])
    s.memory.store(W_PLAYER_BATTLE_STATUS1, i["player_status1"])
    s.memory.store(W_ENEMY_BATTLE_STATUS1, i["enemy_status1"])
    set_assembly_registers(s, i)
    m = p.factory.simulation_manager(s)
    m.explore(find=DONE, num_find=1)
    assert len(m.found) == 1
    x = m.found[0]
    return [
        E(
            a=x.regs.a,
            f=z80_flags_to_sm83(x.regs.f),
            b=x.regs.b,
            c=x.regs.c,
            d=x.regs.d,
            e=x.regs.e,
            h=x.regs.h,
            l=x.regs.l,
            constraints=tuple(x.solver.constraints),
        )
    ]


def native(i: dict, native_symbol: str):
    p = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = p.loader.find_symbol(native_symbol)
    assert fn
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE)
    # battle_attack_count_state struct layout:
    # registers (8 bytes) at offset 0
    # player_attacks_left at offset 8
    # player_battle_status1 at offset 9
    # enemy_attacks_left at offset 10
    # enemy_battle_status1 at offset 11
    store_native_registers(s, NATIVE_STATE, i)
    s.memory.store(NATIVE_STATE + 8, i["player_attacks"])
    s.memory.store(NATIVE_STATE + 9, i["player_status1"])
    s.memory.store(NATIVE_STATE + 10, i["enemy_attacks"])
    s.memory.store(NATIVE_STATE + 11, i["enemy_status1"])
    m = p.factory.simulation_manager(s)
    m.run()
    assert not m.errored
    x = m.deadended[0]
    nr = native_registers(x, NATIVE_STATE)
    return [
        E(
            a=nr["a"],
            f=nr["f"],
            b=nr["b"],
            c=nr["c"],
            d=nr["d"],
            e=nr["e"],
            h=nr["h"],
            l=nr["l"],
            constraints=tuple(x.solver.constraints),
        )
    ]


# For CheckNumAttacksLeft, exclude h and l from equivalence (asm sets them to memory addresses, native preserves them)
CHECK_NUM_ATTACKS_OBSERVABLES = ("a", "f", "b", "c", "d", "e")


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
def test_end_low_health_alarm_equivalence() -> None:
    i = inputs("elh")
    assert_pathwise_equivalent(
        assembly(i, "EndLowHealthAlarm"),
        native(i, "port_end_low_health_alarm"),
        ("a", "f", "b", "c", "d", "e", "h", "l"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
def test_check_num_attacks_left_equivalence() -> None:
    i = inputs("cna")
    assert_pathwise_equivalent(
        assembly(i, "CheckNumAttacksLeft"),
        native(i, "port_check_num_attacks_left"),
        CHECK_NUM_ATTACKS_OBSERVABLES,
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loc1 = symbol_location(SYMBOLS, "EndLowHealthAlarm")
    assert linked_bytes(ROM, loc1, 12) == bytes.fromhex("afea83d0ea2ac03ceaf6ccc9")
    loc2 = symbol_location(SYMBOLS, "CheckNumAttacksLeft")
    assert linked_bytes(ROM, loc2, 20) == bytes.fromhex("fa6ad0a720052162d0cbaefa6fd0a7c02167d0cb")