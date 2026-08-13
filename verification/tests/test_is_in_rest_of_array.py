from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AndImmediate,Sm83CpImmediate,Sm83CpRegister,Sm83IncRegister,Sm83Scf
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;CONTINUE=0xeffc;FOUND=0xeffd;NOTFOUND=0xeffe;BOUNDARY=0xefff
class Bound(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)  # type: ignore[override]
class Fetch(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):  # type: ignore[override]
  if self.state.globals.get("entered",False):self.jump(CONTINUE);return
  self.state.globals["entered"]=True;self.state.regs.a=self.state.globals["fetched"];self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;fetched:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def native(sym,i,ret=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i["fetched"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),fetched=x.memory.load(NATIVE_STATE+8,1),result=(x.regs.rax[7:0] if ret else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
def begin(i):
 loc=symbol_location(SYMBOLS,"IsInRestOfArray");p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address+1,Bound(BOUNDARY),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);x=m.found[0];return E(**assembly_registers(x),fetched=i["fetched"],result=claripy.BVV(0,8),constraints=tuple(x.solver.constraints))
def step(i):
 loc=symbol_location(SYMBOLS,"IsInRestOfArray");loop=loc.address+1;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loop});p.hook(loop,Fetch(loop+1),length=1);p.hook(loop+1,Sm83CpImmediate(0xff,loop+3),length=2);p.hook(loop+5,Sm83CpRegister("c",loop+6),length=1);p.hook(loop+8,Sm83IncRegister("b",loop+9),length=1);p.hook(loop+9,Sm83AddHlRegisterPair("de",loop+10),length=1);p.hook(loop+12,Sm83AndImmediate(0xff,loop+13),length=1);p.hook(loop+13,Bound(NOTFOUND),length=1);p.hook(loop+14,Sm83Scf(FOUND),length=1);s=p.factory.blank_state(addr=loop);set_assembly_registers(s,i);s.globals["fetched"]=i["fetched"];m=p.factory.simulation_manager(s);m.stashes["found"]=[]
 while m.active:
  m.move(from_stash="active",to_stash="found",filter_func=lambda x:x.addr in {CONTINUE,FOUND,NOTFOUND})
  if m.active:m.step()
 return [E(**assembly_registers(x),fetched=i["fetched"],result=claripy.BVV({CONTINUE:0,FOUND:1,NOTFOUND:2}[x.addr],8),constraints=tuple(x.solver.constraints)) for x in m.found]
def inputs(prefix):
 i=symbolic_registers(prefix);i["fetched"]=claripy.BVS(prefix+"_fetched",8);return i
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_begin():
 i=inputs("rest_array_begin");assert_pathwise_equivalent([begin(i)],native("port_is_in_rest_of_array_begin",i),(*REGISTERS,"fetched"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_step():
 i=inputs("rest_array_step");assert_pathwise_equivalent(step(i),native("port_is_in_rest_of_array_step",i,True),(*REGISTERS,"fetched","result"))
def test_body():
 loc=symbol_location(SYMBOLS,"IsInRestOfArray");assert linked_bytes(ROM,loc,17)==bytes.fromhex("4f7efeff2807b92806041918f4a7c937c9")
