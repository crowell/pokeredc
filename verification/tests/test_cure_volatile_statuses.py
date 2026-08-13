from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";STACK=0xd000;RETURN=0xffff;NATIVE_STATE=0x100000
class Res0(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals["memory"][0]=self.state.globals["memory"][0]&0x7f;self.jump(self.n)  # type: ignore[override]
class Load(angr.SimProcedure):
 def __init__(self,n,index):super().__init__();self.n=n;self.index=index
 def run(self):self.state.regs.a=self.state.globals["memory"][self.index];self.jump(self.n)  # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,n,index,increment=False):super().__init__();self.n=n;self.index=index;self.increment=increment
 def run(self):  # type: ignore[override]
  self.state.globals["memory"][self.index]=self.state.regs.a
  if self.increment:self.state.regs.hl=self.state.regs.hl+1
  self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(i):
 loc=symbol_location(SYMBOLS,"CureVolatileStatuses");p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address,Res0(loc.address+2),length=2);p.hook(loc.address+3,Load(loc.address+4,1),length=1);p.hook(loc.address+4,Sm83AndImmediate(0x78,loc.address+6),length=2);p.hook(loc.address+6,Store(loc.address+7,1,True),length=1);p.hook(loc.address+7,Load(loc.address+8,2),length=1);p.hook(loc.address+8,Sm83AndImmediate(0xf8,loc.address+10),length=2);p.hook(loc.address+10,Store(loc.address+11,2),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.globals["memory"]=[i[f"memory{n}"] for n in range(3)];s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness="Iend_LE");ends=collect_returns(p,s,RETURN);return [E(**assembly_registers(x),memory=claripy.Concat(*x.globals["memory"]),constraints=tuple(x.solver.constraints)) for x in ends]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_cure_volatile_statuses");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for n in range(3):s.memory.store(NATIVE_STATE+8+n,i[f"memory{n}"])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=claripy.Concat(*(x.memory.load(NATIVE_STATE+8+n,1) for n in range(3))),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_equivalence():
 i=symbolic_registers("cure_volatile")
 for n in range(3):i[f"memory{n}"]=claripy.BVS(f"cure_volatile_memory{n}",8)
 assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,"memory"))
def test_body():
 loc=symbol_location(SYMBOLS,"CureVolatileStatuses");assert linked_bytes(ROM,loc,12)==bytes.fromhex("cbbe237ee678227ee6f877c9")
