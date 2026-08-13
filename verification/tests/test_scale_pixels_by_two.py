from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AddRegister,Sm83AndImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";STACK=0xd000;RETURN=0xffff;NATIVE_STATE=0x100000
class FetchDuplicate(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):  # type: ignore[override]
  pixels=(self.state.regs.l-0xa8)&0x0f;self.state.regs.a=((pixels&1)*3)|((pixels&2)*6)|((pixels&4)*12)|((pixels&8)*24);self.jump(self.n)
class Store(angr.SimProcedure):
 def __init__(self,n,index,decrement=False):super().__init__();self.n=n;self.index=index;self.decrement=decrement
 def run(self):  # type: ignore[override]
  self.state.globals["written"][self.index]=self.state.regs.a
  if self.decrement:self.state.regs.hl=self.state.regs.hl-1
  self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(i):
 loc=symbol_location(SYMBOLS,"ScalePixelsByTwo");p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address+1,Sm83AndImmediate(0x0f,loc.address+3),length=2);p.hook(loc.address+6,Sm83AddRegister("l",loc.address+7),length=1);p.hook(loc.address+11,FetchDuplicate(loc.address+12),length=1);p.hook(loc.address+13,Store(loc.address+14,0,True),length=1);p.hook(loc.address+14,Store(loc.address+15,1),length=1);p.hook(loc.address+15,Sm83AddHlRegisterPair("bc",loc.address+16),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.globals["written"]=[i["written0"],i["written1"]];s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness="Iend_LE");ends=collect_returns(p,s,RETURN);return [E(**assembly_registers(x),memory=claripy.Concat(*x.globals["written"]),constraints=tuple(x.solver.constraints)) for x in ends]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_scale_pixels_by_two");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i["written0"]);s.memory.store(NATIVE_STATE+9,i["written1"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=claripy.Concat(x.memory.load(NATIVE_STATE+8,1),x.memory.load(NATIVE_STATE+9,1)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_equivalence():
 i=symbolic_registers("scale_pixels");i["written0"]=claripy.BVS("scale_pixels_written0",8);i["written1"]=claripy.BVS("scale_pixels_written1",8);assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,"memory"))
def test_body_and_table():
 loc=symbol_location(SYMBOLS,"ScalePixelsByTwo");table=symbol_location(SYMBOLS,"DuplicateBitsTable");assert linked_bytes(ROM,loc,17)==bytes.fromhex("e5e60f21a87e856f3001247ee1327709c9");assert linked_bytes(ROM,table,16)==bytes.fromhex("00030c0f30333c3fc0c3cccff0f3fcff")
