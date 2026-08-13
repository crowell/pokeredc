from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83OrRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;STACK=0xd000;LOOP=0xeffd;FINISH=0xeffe;BOUNDARY=0xefff
class Bound(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)  # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):  # type: ignore[override]
  if self.state.globals.get("entered",False):self.jump(LOOP);return
  self.state.globals["entered"]=True;self.state.globals["written"]=self.state.regs.a;self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
class DecBC(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):  # type: ignore[override]
  old_c=self.state.regs.c;self.state.regs.c=old_c-1;self.state.regs.b=claripy.If(old_c==0,self.state.regs.b-1,self.state.regs.b);self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def ep(x,saved_d,saved_e,written,result):return E(**assembly_registers(x),memory=claripy.Concat(saved_d,saved_e,written),result=claripy.BVV(result,8),constraints=tuple(x.solver.constraints))
def native(sym,i,ret=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for n,key in enumerate(("saved_d","saved_e","written")):s.memory.store(NATIVE_STATE+8+n,i[key])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=claripy.Concat(*(x.memory.load(NATIVE_STATE+8+n,1) for n in range(3))),result=(x.regs.rax[7:0] if ret else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
def project(loc):return angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address})
def begin(i):
 loc=symbol_location(SYMBOLS,"FillMemory");p=project(loc);p.hook(loc.address+2,Bound(BOUNDARY),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.regs.sp=STACK;m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);return ep(m.found[0],i["d"],i["e"],i["written"],0)
def step(i):
 loc=symbol_location(SYMBOLS,"FillMemory");loop=loc.address+2;p=project(loc);p.hook(loop+1,Store(loop+2),length=1);p.hook(loop+2,DecBC(loop+3),length=1);p.hook(loop+4,Sm83OrRegister("c",loop+5),length=1);p.hook(loop+5,Bound(BOUNDARY),length=2);s=p.factory.blank_state(addr=loop);set_assembly_registers(s,i);s.globals["written"]=i["written"];m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);x=m.found[0];base=dict(assembly_registers(x));memory=claripy.Concat(i["saved_d"],i["saved_e"],x.globals["written"]);constraints=tuple(x.solver.constraints);return [E(**base,memory=memory,result=claripy.BVV(1,8),constraints=constraints+(base["a"]==0,)),E(**base,memory=memory,result=claripy.BVV(0,8),constraints=constraints+(base["a"]!=0,))]
def finish(i):
 loc=symbol_location(SYMBOLS,"FillMemory");p=project(loc);s=p.factory.blank_state(addr=loc.address+9);set_assembly_registers(s,i);s.regs.sp=STACK;s.memory.store(STACK,claripy.Concat(i["saved_d"],i["saved_e"]),endness="Iend_LE");p.hook(loc.address+10,Bound(BOUNDARY),length=1);m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);return ep(m.found[0],i["saved_d"],i["saved_e"],i["written"],0)
def inputs(prefix):
 i=symbolic_registers(prefix);i["saved_d"]=claripy.BVS(prefix+"_saved_d",8);i["saved_e"]=claripy.BVS(prefix+"_saved_e",8);i["written"]=claripy.BVS(prefix+"_written",8);return i
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_begin():
 i=inputs("fill_begin");assert_pathwise_equivalent([begin(i)],native("port_fill_memory_begin",i),(*REGISTERS,"memory"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_step():
 i=inputs("fill_step");assert_pathwise_equivalent(step(i),native("port_fill_memory_step",i,True),(*REGISTERS,"memory","result"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_finish():
 i=inputs("fill_finish");assert_pathwise_equivalent([finish(i)],native("port_fill_memory_finish",i),(*REGISTERS,"memory"))
def test_body():
 loc=symbol_location(SYMBOLS,"FillMemory");assert linked_bytes(ROM,loc,11)==bytes.fromhex("d5577a220b78b120f9d1c9")
