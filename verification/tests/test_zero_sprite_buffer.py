from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83OrRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;BOUNDARY=0xefff
class Bound(angr.SimProcedure):
 def run(self):self.jump(BOUNDARY)  # type: ignore[override]
class XorStore(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=0;self.state.regs.f=0x40;self.state.globals["written"]=claripy.BVV(0,8);self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
class DecBC(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):  # type: ignore[override]
  old_c=self.state.regs.c;self.state.regs.c=old_c-1;self.state.regs.b=claripy.If(old_c==0,self.state.regs.b-1,self.state.regs.b);self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;written:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def native(sym,i,ret=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i["written"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),written=x.memory.load(NATIVE_STATE+8,1),result=(x.regs.rax[7:0] if ret else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
def begin(i):
 loc=symbol_location(SYMBOLS,"ZeroSpriteBuffer");p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address+3,Bound(),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);x=m.found[0];return E(**assembly_registers(x),written=i["written"],result=claripy.BVV(0,8),constraints=tuple(x.solver.constraints))
def step(i):
 loc=symbol_location(SYMBOLS,"ZeroSpriteBuffer");loop=loc.address+3;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loop});p.hook(loop,XorStore(loop+2),length=2);p.hook(loop+2,DecBC(loop+3),length=1);p.hook(loop+4,Sm83OrRegister("c",loop+5),length=1);p.hook(loop+5,Bound(),length=2);s=p.factory.blank_state(addr=loop);set_assembly_registers(s,i);s.globals["written"]=i["written"];m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);x=m.found[0];base=dict(assembly_registers(x));constraints=tuple(x.solver.constraints);return [E(**base,written=x.globals["written"],result=claripy.BVV(1,8),constraints=constraints+(base["a"]==0,)),E(**base,written=x.globals["written"],result=claripy.BVV(0,8),constraints=constraints+(base["a"]!=0,))]
def inputs(prefix):
 i=symbolic_registers(prefix);i["written"]=claripy.BVS(prefix+"_written",8);return i
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_begin():
 i=inputs("zero_sprite_begin");assert_pathwise_equivalent([begin(i)],native("port_zero_sprite_buffer_begin",i),(*REGISTERS,"written"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_step():
 i=inputs("zero_sprite_step");assert_pathwise_equivalent(step(i),native("port_zero_sprite_buffer_step",i,True),(*REGISTERS,"written","result"))
def test_body():
 loc=symbol_location(SYMBOLS,"ZeroSpriteBuffer");assert linked_bytes(ROM,loc,11)==bytes.fromhex("018801af220b78b120f9c9")
