from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83BitAtHl,Sm83LoadAHighImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";STACK=0xc000;RETURN=0xffff;NATIVE_STATE=0x100000
NAMES=("hWhoseTurn","wPlayerBattleStatus2","wEnemyBattleStatus2")
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(i):
 loc=symbol_location(SYMBOLS,"CheckTargetSubstitute");a=tuple(symbol_location(SYMBOLS,n).address for n in NAMES);p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address+4,Sm83LoadAHighImmediate(a[0],loc.address+6),length=2);p.hook(loc.address+6,Sm83AndImmediate(0xff,loc.address+7),length=1);p.hook(loc.address+13,Sm83BitAtHl(4,loc.address+15),length=2);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i)
 for n,address in enumerate(a):s.memory.store(address,i[f"memory{n}"])
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness="Iend_LE");ends=collect_returns(p,s,RETURN);return [E(**assembly_registers(x),memory=claripy.Concat(*(x.memory.load(v,1) for v in a)),constraints=tuple(x.solver.constraints)) for x in ends]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_check_target_substitute");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for n in range(3):s.memory.store(NATIVE_STATE+8+n,i[f"memory{n}"])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=claripy.Concat(*(x.memory.load(NATIVE_STATE+8+n,1) for n in range(3))),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_equivalence():
 i=symbolic_registers("target_substitute")
 for n,name in enumerate(NAMES):i[f"memory{n}"]=claripy.BVS("target_substitute_"+name,8)
 assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,"memory"))
def test_body():
 loc=symbol_location(SYMBOLS,"CheckTargetSubstitute");assert linked_bytes(ROM,loc,16)==bytes.fromhex("e52168d0f0f3a728032163d0cb66e1c9")
