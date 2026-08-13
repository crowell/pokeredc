from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate,Sm83IncRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;LOOP=0xeffe;RETURN=0xefff
class BeginBoundary(angr.SimProcedure):
 def run(self)->None:self.jump(LOOP)  # type: ignore[override]
class Fetched(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:self.state.regs.a=self.state.globals["fetched"];self.jump(self.n)  # type: ignore[override]
class RetZ(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:  # type: ignore[override]
  self.inhibit_autoret=True;self.successors.add_successor(self.state.copy(),RETURN,(self.state.regs.f&0x40)!=0,"Ijk_Boring");self.successors.add_successor(self.state.copy(),self.n,(self.state.regs.f&0x40)==0,"Ijk_Boring")
class LoopBoundary(angr.SimProcedure):
 def run(self)->None:self.jump(LOOP)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;cont:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def native(sym:str,i:dict[str,claripy.ast.BV],fetched:bool)->list[E]:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;args=(fn.rebased_addr,NATIVE_STATE,claripy.ZeroExt(56,i["fetched"])) if fetched else (fn.rebased_addr,NATIVE_STATE);s=p.factory.call_state(*args);store_native_registers(s,NATIVE_STATE,i);m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),cont=(claripy.If(x.regs.rax[7:0]==0,claripy.BVV(1,8),claripy.BVV(0,8)) if fetched else claripy.BVV(1,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
def begin(i:dict[str,claripy.ast.BV])->E:
 loc=symbol_location(SYMBOLS,"CalcStringLength");p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address+5,BeginBoundary(),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);m=p.factory.simulation_manager(s);m.explore(find=LOOP);x=m.found[0];return E(**assembly_registers(x),cont=claripy.BVV(1,8),constraints=tuple(x.solver.constraints))
def step(i:dict[str,claripy.ast.BV])->list[E]:
 loc=symbol_location(SYMBOLS,"CalcStringLength");loop=loc.address+5;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loop});p.hook(loop,Fetched(loop+1),length=1);p.hook(loop+1,Sm83CpImmediate(0x50,loop+3),length=2);p.hook(loop+3,RetZ(loop+4),length=1);p.hook(loop+5,Sm83IncRegister("c",loop+6),length=1);p.hook(loop+6,LoopBoundary(),length=2);s=p.factory.blank_state(addr=loop);set_assembly_registers(s,i);s.globals["fetched"]=i["fetched"];m=p.factory.simulation_manager(s);m.explore(find=lambda x:x.addr in {LOOP,RETURN},num_find=2);assert not m.errored
 return [E(**assembly_registers(x),cont=claripy.BVV(1 if x.addr==LOOP else 0,8),constraints=tuple(x.solver.constraints)) for x in m.found]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_begin()->None:
 i=symbolic_registers("calc_length_begin");i["fetched"]=claripy.BVS("unused_fetched",8);assert_pathwise_equivalent([begin(i)],native("port_calc_string_length_begin",i,False),(*REGISTERS,"cont"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_step()->None:
 i=symbolic_registers("calc_length_step");i["fetched"]=claripy.BVS("calc_length_fetched",8);assert_pathwise_equivalent(step(i),native("port_calc_string_length_step",i,True),(*REGISTERS,"cont"))
def test_body()->None:
 loc=symbol_location(SYMBOLS,"CalcStringLength");assert linked_bytes(ROM,loc,13)==bytes.fromhex("214bcf0e007efe50c8230c18f8")
