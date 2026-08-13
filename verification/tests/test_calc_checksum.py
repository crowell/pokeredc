from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddRegister,Sm83OrRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;CONTINUE=0xeffe;FINISH=0xefff
class Bound(angr.SimProcedure):
 def __init__(self,target:int)->None:super().__init__();self.target=target
 def run(self)->None:self.jump(self.target)  # type: ignore[override]
class FetchLoop(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:  # type: ignore[override]
  if self.state.globals.get("entered",False):self.jump(CONTINUE);return
  self.state.globals["entered"]=True;self.state.regs.a=self.state.globals["fetched"];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
class Cpl(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:self.state.regs.a=~self.state.regs.a;self.state.regs.f=(self.state.regs.f&0x41)|0x12;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;fetched:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def project(loc):return angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address})
def ep(x,i,result):return E(**assembly_registers(x),fetched=i["fetched"],result=claripy.BVV(result,8),constraints=tuple(x.solver.constraints))
def native(sym,i,ret=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i["fetched"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),fetched=x.memory.load(NATIVE_STATE+8,1),result=(x.regs.rax[7:0] if ret else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
def begin(i):
 loc=symbol_location(SYMBOLS,"CalcCheckSum");p=project(loc);p.hook(loc.address+2,Bound(FINISH),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);m=p.factory.simulation_manager(s);m.explore(find=FINISH);return ep(m.found[0],i,0)
def step(i):
 loc=symbol_location(SYMBOLS,"CalcCheckSum");loop=loc.address+2;p=project(loc);p.hook(loop,FetchLoop(loop+1),length=1);p.hook(loop+1,Sm83AddRegister("d",loop+2),length=1);p.hook(loop+5,Sm83OrRegister("c",loop+6),length=1);p.hook(loop+8,Bound(FINISH),length=1);s=p.factory.blank_state(addr=loop);set_assembly_registers(s,i);s.globals["fetched"]=i["fetched"];m=p.factory.simulation_manager(s);m.stashes["found"]=[]
 while m.active:
  m.move(from_stash="active",to_stash="found",filter_func=lambda x:x.addr in {CONTINUE,FINISH})
  if m.active:m.step()
 return [ep(x,i,1 if x.addr==FINISH else 0) for x in m.found]
def finish(i):
 loc=symbol_location(SYMBOLS,"CalcCheckSum");start=loc.address+10;p=project(loc);p.hook(start+1,Cpl(FINISH),length=1);s=p.factory.blank_state(addr=start);set_assembly_registers(s,i);m=p.factory.simulation_manager(s);m.explore(find=FINISH);return ep(m.found[0],i,0)
def inputs(prefix):
 i=symbolic_registers(prefix);i["fetched"]=claripy.BVS(prefix+"_fetched",8);return i
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_begin():
 i=inputs("checksum_begin");assert_pathwise_equivalent([begin(i)],native("port_calc_checksum_begin",i),(*REGISTERS,"fetched"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_step():
 i=inputs("checksum_step");assert_pathwise_equivalent(step(i),native("port_calc_checksum_step",i,True),(*REGISTERS,"fetched","result"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_finish():
 i=inputs("checksum_finish");assert_pathwise_equivalent([finish(i)],native("port_calc_checksum_finish",i),(*REGISTERS,"fetched"))
def test_body():
 loc=symbol_location(SYMBOLS,"CalcCheckSum");assert linked_bytes(ROM,loc,13)==bytes.fromhex("16002a82570b78b120f87a2fc9")
