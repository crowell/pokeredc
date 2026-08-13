from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83CpImmediate,Sm83CpRegister,Sm83LoadAImmediate,Sm83Scf
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";STACK=0xd000;RETURN=0xffff;NATIVE_STATE=0x100000
NAMES=("wTrainerEngageDistance","wTrainerFacingDirection","wTrainerScreenY","wTrainerScreenX")
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(i:dict[str,claripy.ast.BV])->list[E]:
 loc=symbol_location(SYMBOLS,"CheckSpriteCanSeePlayer");a=tuple(symbol_location(SYMBOLS,n).address for n in NAMES);p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address+1,Sm83LoadAImmediate(a[0],loc.address+4),length=3);p.hook(loc.address+4,Sm83CpRegister("b",loc.address+5),length=1);p.hook(loc.address+9,Sm83LoadAImmediate(a[1],loc.address+12),length=3)
 for off,val in ((12,0),(16,4),(20,8),(24,12),(34,0x40),(44,0x3c)):p.hook(loc.address+off,Sm83CpImmediate(val,loc.address+off+2),length=2)
 p.hook(loc.address+30,Sm83LoadAImmediate(a[3],loc.address+33),length=3);p.hook(loc.address+40,Sm83LoadAImmediate(a[2],loc.address+43),length=3);p.hook(loc.address+48,Sm83Scf(loc.address+49),length=1);p.hook(loc.address+50,Sm83AndImmediate(0xff,loc.address+51),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i)
 for n,v in enumerate(a):s.memory.store(v,i[f"memory{n}"])
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness="Iend_LE");ends=collect_returns(p,s,RETURN);return [E(**assembly_registers(x),memory=claripy.Concat(*(x.memory.load(v,1) for v in a)),constraints=tuple(x.solver.constraints)) for x in ends]
def native(i:dict[str,claripy.ast.BV])->list[E]:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_check_sprite_can_see_player");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for n in range(4):s.memory.store(NATIVE_STATE+8+n,i[f"memory{n}"])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,4),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_equivalence()->None:
 i=symbolic_registers("check_sprite_can_see")
 for n,name in enumerate(("distance","facing","screen_y","screen_x")):i[f"memory{n}"]=claripy.BVS("trainer_"+name,8)
 assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,"memory"))
def test_body()->None:
 loc=symbol_location(SYMBOLS,"CheckSpriteCanSeePlayer");assert linked_bytes(ROM,loc,52)==bytes.fromhex("47fa3ecdb830021829fa3fcdfe00280efe04280afe082810fe0c280c1814fa41cd47fe40280a180afa40cd47fe3c200237c9a7c9")
