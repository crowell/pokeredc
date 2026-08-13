from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83OrRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;LOOP=0xeffe;RETURN=0xefff
class OneStep(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:  # type: ignore[override]
  if self.state.globals.get("entered",False):self.jump(LOOP);return
  self.state.globals["entered"]=True;self.state.globals["written"]=claripy.BVV(0,8);self.state.regs.hl=self.state.regs.hl+2;self.state.regs.bc=self.state.regs.bc-1;self.jump(self.n)
class Bound(angr.SimProcedure):
 def run(self)->None:self.jump(RETURN)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;written:claripy.ast.BV;cont:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(i:dict[str,claripy.ast.BV])->list[E]:
 loc=symbol_location(SYMBOLS,"ShiftFontColorIndex");p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address,OneStep(loc.address+5),length=5);p.hook(loc.address+6,Sm83OrRegister("c",loc.address+7),length=1);p.hook(loc.address+9,Bound(),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.globals["written"]=i["written"];m=p.factory.simulation_manager(s);m.stashes["found"]=[]
 while m.active:
  m.move(from_stash="active",to_stash="found",filter_func=lambda x:x.addr in {LOOP,RETURN})
  if m.active:m.step()
 return [E(**assembly_registers(x),written=x.globals["written"],cont=claripy.BVV(1 if x.addr==LOOP else 0,8),constraints=tuple(x.solver.constraints)) for x in m.found]
def native(i:dict[str,claripy.ast.BV])->list[E]:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_shift_font_color_index_step");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i["written"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),written=x.memory.load(NATIVE_STATE+8,1),cont=claripy.If(x.regs.rax[7:0]==0,claripy.BVV(1,8),claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_step()->None:
 i=symbolic_registers("shift_font_step");i["written"]=claripy.BVS("shift_font_written",8);assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,"written","cont"))
def test_body()->None:
 loc=symbol_location(SYMBOLS,"ShiftFontColorIndex");assert linked_bytes(ROM,loc,10)==bytes.fromhex("360023230b78b120f7c9")
