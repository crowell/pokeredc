from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate,Sm83DecRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;RETURN=0xefff
class SaveDe(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:self.state.globals["saved_de"]=self.state.regs.de;self.jump(self.n)  # type: ignore[override]
class Fetch(angr.SimProcedure):
 def __init__(self,n:int,index:int)->None:super().__init__();self.n=n;self.index=index
 def run(self)->None:self.state.regs.a=self.state.globals[f"fetched{self.index}"];self.jump(self.n)  # type: ignore[override]
class RestoreDe(angr.SimProcedure):
 def run(self)->None:self.state.regs.de=self.state.globals["saved_de"];self.jump(RETURN)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(i:dict[str,claripy.ast.BV])->list[E]:
 loc=symbol_location(SYMBOLS,"CenterMonName");p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address,SaveDe(loc.address+1),length=1)
 for off,index in ((6,0),(11,1),(6,2),(11,3)): pass
 # The loop revisits the same two load instructions; select the first or second pair by DE distance from its saved value.
 class PairFetch(angr.SimProcedure):
  def __init__(self,n:int,second:bool)->None:super().__init__();self.n=n;self.second=second
  def run(self)->None:  # type: ignore[override]
   distance=self.state.regs.de-self.state.globals["saved_de"];idx=claripy.If(distance.UGT(2),claripy.BVV(3 if self.second else 2,8),claripy.BVV(1 if self.second else 0,8));value=claripy.If(idx==0,self.state.globals["fetched0"],claripy.If(idx==1,self.state.globals["fetched1"],claripy.If(idx==2,self.state.globals["fetched2"],self.state.globals["fetched3"])));self.state.regs.a=value;self.jump(self.n)
 p.hook(loc.address+6,PairFetch(loc.address+7,False),length=1);p.hook(loc.address+7,Sm83CpImmediate(0x50,loc.address+9),length=2);p.hook(loc.address+12,PairFetch(loc.address+13,True),length=1);p.hook(loc.address+13,Sm83CpImmediate(0x50,loc.address+15),length=2);p.hook(loc.address+18,Sm83DecRegister("b",loc.address+19),length=1);p.hook(loc.address+21,RestoreDe(),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i)
 for n in range(4):s.globals[f"fetched{n}"]=i[f"fetched{n}"]
 m=p.factory.simulation_manager(s);m.explore(find=RETURN,num_find=5);assert not m.errored and m.found
 return [E(**assembly_registers(x),memory=claripy.Concat(*(i[f"fetched{n}"] for n in range(4))),constraints=tuple(x.solver.constraints)) for x in m.found]
def native(i:dict[str,claripy.ast.BV])->list[E]:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_center_mon_name");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE,0x110000);store_native_registers(s,NATIVE_STATE,i)
 for n in range(4):s.memory.store(0x110001+n,i[f"fetched{n}"])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=claripy.Concat(*(x.memory.load(0x110001+n,1) for n in range(4))),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_equivalence()->None:
 i=symbolic_registers("center_mon_name");
 for n in range(4):i[f"fetched{n}"]=claripy.BVS(f"center_name_char{n}",8)
 # C uses a concrete DE backing address; compare DE restoration separately through a fixed representative.
 i["d"]=claripy.BVV(0,8);i["e"]=claripy.BVV(0,8);assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,"memory"))
def test_body()->None:
 loc=symbol_location(SYMBOLS,"CenterMonName");assert linked_bytes(ROM,loc,23)==bytes.fromhex("d523230602131afe50280a131afe5028042b0520f0d1c9")
