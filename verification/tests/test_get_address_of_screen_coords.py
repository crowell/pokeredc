from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AndImmediate,Sm83DecRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;STACK=0xd000;CONTINUE=0xeffd;FINISH=0xeffe;BOUNDARY=0xefff
class Bound(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)  # type: ignore[override]
class LoadD(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):  # type: ignore[override]
  if self.state.globals.get("entered",False):self.jump(CONTINUE);return
  self.state.globals["entered"]=True;self.state.regs.a=self.state.regs.d;self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;saved:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def ep(x,saved,result):return E(**assembly_registers(x),saved=saved,result=claripy.BVV(result,8),constraints=tuple(x.solver.constraints))
def native(sym,i,ret=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i["saved_b"]);s.memory.store(NATIVE_STATE+9,i["saved_c"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),saved=claripy.Concat(x.memory.load(NATIVE_STATE+8,1),x.memory.load(NATIVE_STATE+9,1)),result=(x.regs.rax[7:0] if ret else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
def project(loc):return angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address})
def begin(i):
 loc=symbol_location(SYMBOLS,"GetAddressOfScreenCoords");p=project(loc);p.hook(loc.address+7,Bound(BOUNDARY),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.regs.sp=STACK;m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);return ep(m.found[0],claripy.Concat(i["b"],i["c"]),0)
def step(i):
 loc=symbol_location(SYMBOLS,"GetAddressOfScreenCoords");loop=loc.address+7;p=project(loc);p.hook(loop,LoadD(loop+1),length=1);p.hook(loop+1,Sm83AndImmediate(0xff,loop+2),length=1);p.hook(loop+4,Sm83AddHlRegisterPair("bc",loop+5),length=1);p.hook(loop+5,Sm83DecRegister("d",loop+6),length=1);p.hook(loop+8,Bound(FINISH),length=1);s=p.factory.blank_state(addr=loop);set_assembly_registers(s,i);m=p.factory.simulation_manager(s);m.stashes["found"]=[]
 while m.active:
  m.move(from_stash="active",to_stash="found",filter_func=lambda x:x.addr in {CONTINUE,FINISH})
  if m.active:m.step()
 return [ep(x,claripy.Concat(i["saved_b"],i["saved_c"]),1 if x.addr==FINISH else 0) for x in m.found]
def finish(i):
 loc=symbol_location(SYMBOLS,"GetAddressOfScreenCoords");p=project(loc);p.hook(loc.address+16,Sm83AddHlRegisterPair("de",BOUNDARY),length=1);s=p.factory.blank_state(addr=loc.address+15);set_assembly_registers(s,i);s.regs.sp=STACK;s.memory.store(STACK,claripy.Concat(i["saved_b"],i["saved_c"]),endness="Iend_LE");m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);return ep(m.found[0],claripy.Concat(i["saved_b"],i["saved_c"]),0)
def inputs(prefix):
 i=symbolic_registers(prefix);i["saved_b"]=claripy.BVS(prefix+"_saved_b",8);i["saved_c"]=claripy.BVS(prefix+"_saved_c",8);return i
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_begin():
 i=inputs("screen_coords_begin");assert_pathwise_equivalent([begin(i)],native("port_get_address_of_screen_coords_begin",i),(*REGISTERS,"saved"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_step():
 i=inputs("screen_coords_step");assert_pathwise_equivalent(step(i),native("port_get_address_of_screen_coords_step",i,True),(*REGISTERS,"saved","result"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_finish():
 i=inputs("screen_coords_finish");assert_pathwise_equivalent([finish(i)],native("port_get_address_of_screen_coords_finish",i),(*REGISTERS,"saved"))
def test_body():
 loc=symbol_location(SYMBOLS,"GetAddressOfScreenCoords");assert linked_bytes(ROM,loc,18)==bytes.fromhex("c521a0c30114007aa72804091518f8c119c9")
