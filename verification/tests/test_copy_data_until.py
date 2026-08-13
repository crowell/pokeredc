from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83CpRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;CONTINUE=0xeffe;DONE=0xefff
class Fetch(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):  # type: ignore[override]
  if self.state.globals.get("entered",False):self.jump(CONTINUE);return
  self.state.globals["entered"]=True;self.state.regs.a=self.state.globals["fetched"];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
class Store(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals["written"]=self.state.regs.a;self.jump(self.n)  # type: ignore[override]
class Bound(angr.SimProcedure):
 def run(self):self.jump(DONE)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(i):
 loc=symbol_location(SYMBOLS,"CopyDataUntil");p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address,Fetch(loc.address+1),length=1);p.hook(loc.address+1,Store(loc.address+2),length=1);p.hook(loc.address+4,Sm83CpRegister("b",loc.address+5),length=1);p.hook(loc.address+8,Sm83CpRegister("c",loc.address+9),length=1);p.hook(loc.address+11,Bound(),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.globals["fetched"]=i["fetched"];s.globals["written"]=i["written"];m=p.factory.simulation_manager(s);m.stashes["found"]=[]
 while m.active:
  m.move(from_stash="active",to_stash="found",filter_func=lambda x:x.addr in {CONTINUE,DONE})
  if m.active:m.step()
 return [E(**assembly_registers(x),memory=claripy.Concat(i["fetched"],x.globals["written"]),result=claripy.BVV(1 if x.addr==DONE else 0,8),constraints=tuple(x.solver.constraints)) for x in m.found]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_copy_data_until_step");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i["fetched"]);s.memory.store(NATIVE_STATE+9,i["written"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=claripy.Concat(x.memory.load(NATIVE_STATE+8,1),x.memory.load(NATIVE_STATE+9,1)),result=x.regs.rax[7:0],constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_step():
 i=symbolic_registers("copy_data_until");i["fetched"]=claripy.BVS("copy_data_until_fetched",8);i["written"]=claripy.BVS("copy_data_until_written",8);assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,"memory","result"))
def test_body():
 loc=symbol_location(SYMBOLS,"CopyDataUntil");assert linked_bytes(ROM,loc,12)==bytes.fromhex("2a12137cb820f97db920f5c9")
