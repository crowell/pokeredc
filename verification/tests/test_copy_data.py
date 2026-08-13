from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83OrRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xefff
class Fetch(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=self.state.globals['fetched'];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['written']=self.state.regs.a;self.jump(self.n)  # type: ignore[override]
class Bound(angr.SimProcedure):
 def run(self):self.state.globals['result']=claripy.If(self.state.regs.bc==0,claripy.BVV(1,8),claripy.BVV(0,8));self.jump(DONE)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p);i['fetched']=claripy.BVS(f'{p}_fetched',8);i['written']=claripy.BVS(f'{p}_written',8);return i
def assembly(i):
 l=symbol_location(SYMBOLS,'CopyData');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q,Fetch(q+1),length=1);p.hook(q+1,Store(q+2),length=1);p.hook(q+5,Sm83OrRegister('b',q+6),length=1);p.hook(q+6,Bound(),length=2);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.globals['fetched']=i['fetched'];s.globals['written']=i['written'];m=p.factory.simulation_manager(s);m.explore(find=DONE);assert len(m.found)==1;x=m.found[0];return [E(**assembly_registers(x),memory=claripy.Concat(x.globals['fetched'],x.globals['written']),result=x.globals['result'],constraints=tuple(x.solver.constraints))]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_copy_data_step');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i['fetched']);s.memory.store(NATIVE_STATE+9,i['written']);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,2),result=x.regs.rax[7:0],constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_transition_equivalence():
 i=inputs('copy_data');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory','result'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'CopyData');assert linked_bytes(ROM,l,9)==bytes.fromhex('2a12130b79b020f8c9')
