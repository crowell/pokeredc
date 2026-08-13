from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddImmediate,Sm83AndImmediate,Sm83CpImmediate,Sm83IncRegister,Sm83LoadAHighImmediate,Sm83StoreAHighImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";STACK=0xd000;RETURN=0xffff;NATIVE_STATE=0x100000
class Load(angr.SimProcedure):
 def __init__(self,n:int,key:str)->None:super().__init__();self.n=n;self.key=key
 def run(self)->None:self.state.regs.a=self.state.globals[self.key];self.jump(self.n)  # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,n:int,key:str)->None:super().__init__();self.n=n;self.key=key
 def run(self)->None:self.state.globals[self.key]=self.state.regs.a;self.jump(self.n)  # type: ignore[override]
class Zero(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:self.state.regs.a=0;self.state.regs.f=0x40;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(i:dict[str,claripy.ast.BV])->list[E]:
 loc=symbol_location(SYMBOLS,"AdvanceScriptedNPCAnimFrameCounter");current=symbol_location(SYMBOLS,"hCurrentSpriteOffset").address;output=symbol_location(SYMBOLS,"hSpriteAnimFrameCounter").address;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address,Sm83LoadAHighImmediate(current,loc.address+2),length=2);p.hook(loc.address+2,Sm83AddImmediate(7,loc.address+4),length=2);p.hook(loc.address+5,Load(loc.address+6,"intra"),length=1);p.hook(loc.address+6,Sm83IncRegister("a",loc.address+7),length=1);p.hook(loc.address+7,Store(loc.address+8,"intra"),length=1);p.hook(loc.address+8,Sm83CpImmediate(4,loc.address+10),length=2);p.hook(loc.address+11,Zero(loc.address+12),length=1);p.hook(loc.address+12,Store(loc.address+13,"intra"),length=1);p.hook(loc.address+14,Load(loc.address+15,"animation"),length=1);p.hook(loc.address+15,Sm83IncRegister("a",loc.address+16),length=1);p.hook(loc.address+16,Sm83AndImmediate(3,loc.address+18),length=2);p.hook(loc.address+18,Store(loc.address+19,"animation"),length=1);p.hook(loc.address+19,Sm83StoreAHighImmediate(output,loc.address+21),length=2);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.memory.store(current,i["current"]);s.memory.store(output,i["output"]);s.globals["intra"]=i["intra"];s.globals["animation"]=i["animation"];s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness="Iend_LE");ends=collect_returns(p,s,RETURN);return [E(**assembly_registers(x),memory=claripy.Concat(x.memory.load(current,1),x.globals["intra"],x.globals["animation"],x.memory.load(output,1)),constraints=tuple(x.solver.constraints)) for x in ends]
def native(i:dict[str,claripy.ast.BV])->list[E]:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_advance_scripted_npc_anim_frame_counter");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for n,key in enumerate(("current","intra","animation","output"),8):s.memory.store(NATIVE_STATE+n,i[key])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,4),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_equivalence()->None:
 i=symbolic_registers("advance_npc_anim")
 for key in ("current","intra","animation","output"):i[key]=claripy.BVS("advance_"+key,8)
 assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,"memory"))
def test_body()->None:
 loc=symbol_location(SYMBOLS,"AdvanceScriptedNPCAnimFrameCounter");assert linked_bytes(ROM,loc,22)==bytes.fromhex("f0dac6076f7e3c77fe04c0af772c7e3ce60377e0eac9")
