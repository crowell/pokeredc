from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AddImmediate,Sm83LoadAImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";STACK=0xd000;RETURN=0xffff;NATIVE_STATE=0x100000
class Fetch(angr.SimProcedure):
 def __init__(self,n:int,key:str)->None:super().__init__();self.n=n;self.key=key
 def run(self)->None:self.state.regs.a=self.state.globals[self.key];self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(i:dict[str,claripy.ast.BV])->E:
 loc=symbol_location(SYMBOLS,"ReadTrainerScreenPosition");names=("wTrainerSpriteOffset","wTrainerScreenY","wTrainerScreenX");a=tuple(symbol_location(SYMBOLS,n).address for n in names);p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address})
 p.hook(loc.address,Sm83LoadAImmediate(a[0],loc.address+3),length=3);p.hook(loc.address+3,Sm83AddImmediate(4,loc.address+5),length=2);p.hook(loc.address+11,Sm83AddHlRegisterPair("de",loc.address+12),length=1);p.hook(loc.address+12,Fetch(loc.address+13,"fetched_y"),length=1);p.hook(loc.address+13,Sm83StoreAImmediate(a[1],loc.address+16),length=3);p.hook(loc.address+16,Sm83LoadAImmediate(a[0],loc.address+19),length=3);p.hook(loc.address+19,Sm83AddImmediate(6,loc.address+21),length=2);p.hook(loc.address+27,Sm83AddHlRegisterPair("de",loc.address+28),length=1);p.hook(loc.address+28,Fetch(loc.address+29,"fetched_x"),length=1);p.hook(loc.address+29,Sm83StoreAImmediate(a[2],loc.address+32),length=3)
 s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.memory.store(a[0],i["sprite_offset"]);s.memory.store(a[1],i["screen_y"]);s.memory.store(a[2],i["screen_x"]);s.globals["fetched_y"]=i["fetched_y"];s.globals["fetched_x"]=i["fetched_x"];s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness="Iend_LE");x=collect_returns(p,s,RETURN)[0];return E(**assembly_registers(x),memory=claripy.Concat(x.memory.load(a[0],1),i["fetched_y"],i["fetched_x"],x.memory.load(a[1],1),x.memory.load(a[2],1)),constraints=tuple(x.solver.constraints))
def native(i:dict[str,claripy.ast.BV])->E:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_read_trainer_screen_position");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for off,key in enumerate(("sprite_offset","fetched_y","fetched_x","screen_y","screen_x"),8):s.memory.store(NATIVE_STATE+off,i[key])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1;x=m.deadended[0];return E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,5),constraints=tuple(x.solver.constraints))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_equivalence()->None:
 i=symbolic_registers("trainer_screen_position")
 for key in ("sprite_offset","fetched_y","fetched_x","screen_y","screen_x"):i[key]=claripy.BVS("trainer_"+key,8)
 assert_pathwise_equivalent([assembly(i)],[native(i)],(*REGISTERS,"memory"))
def test_body()->None:
 loc=symbol_location(SYMBOLS,"ReadTrainerScreenPosition");assert linked_bytes(ROM,loc,33)==bytes.fromhex("fa3dcdc60416005f2100c1197eea40cdfa3dcdc60616005f2100c1197eea41cdc9")
