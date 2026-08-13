from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83DecRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;LOOP=0xeffe;RETURN=0xefff
class Store(angr.SimProcedure):
 def __init__(self,n,index,delta):super().__init__();self.n=n;self.index=index;self.delta=delta
 def run(self):  # type: ignore[override]
  if self.index==0 and self.state.globals.get("entered",False):self.jump(LOOP);return
  self.state.globals["entered"]=True;self.state.globals["written"][self.index]=self.state.regs.a;self.state.regs.hl=self.state.regs.hl+self.delta;self.jump(self.n)
class Bound(angr.SimProcedure):
 def run(self):self.jump(RETURN)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;written:claripy.ast.BV;cont:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(i):
 loc=symbol_location(SYMBOLS,"StatusScreen_PrintPP");p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address,Store(loc.address+1,0,1),length=1);p.hook(loc.address+1,Store(loc.address+2,1,-1),length=1);p.hook(loc.address+2,Sm83AddHlRegisterPair("de",loc.address+3),length=1);p.hook(loc.address+3,Sm83DecRegister("c",loc.address+4),length=1);p.hook(loc.address+6,Bound(),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.globals["written"]=[i["written0"],i["written1"]];m=p.factory.simulation_manager(s);m.stashes["found"]=[]
 while m.active:
  m.move(from_stash="active",to_stash="found",filter_func=lambda x:x.addr in {LOOP,RETURN})
  if m.active:m.step()
 return [E(**assembly_registers(x),written=claripy.Concat(*x.globals["written"]),cont=claripy.BVV(1 if x.addr==LOOP else 0,8),constraints=tuple(x.solver.constraints)) for x in m.found]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_status_screen_print_pp_step");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i["written0"]);s.memory.store(NATIVE_STATE+9,i["written1"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),written=claripy.Concat(x.memory.load(NATIVE_STATE+8,1),x.memory.load(NATIVE_STATE+9,1)),cont=claripy.If(x.regs.rax[7:0]==0,claripy.BVV(1,8),claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_step():
 i=symbolic_registers("status_pp");i["written0"]=claripy.BVS("status_pp_written0",8);i["written1"]=claripy.BVS("status_pp_written1",8);assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,"written","cont"))
def test_body():
 loc=symbol_location(SYMBOLS,"StatusScreen_PrintPP");assert linked_bytes(ROM,loc,7)==bytes.fromhex("2232190d20fac9")
