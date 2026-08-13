from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83DecRegister,Sm83IncRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff
class Save(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  for r in ('b','c','d','e','h','l'):self.state.globals['saved_'+r]=getattr(self.state.regs,r)
  self.jump(self.n)  # type: ignore[override]
class Skip(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)  # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  i=self.state.globals['index'];self.state.globals[f'write{i}']=self.state.regs.d;self.state.globals['index']=i+1;self.jump(self.n)  # type: ignore[override]
class Restore(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  for r in ('b','c','d','e','h','l'):setattr(self.state.regs,r,self.state.globals['saved_'+r])
  self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):i=symbolic_registers(p);i['writes']=claripy.BVS(p+'_writes',56);return i
def assembly(i):
 l=symbol_location(SYMBOLS,'DrawTrainerPicColumn');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q,Save(q+1),length=1);p.hook(q+1,Skip(q+2),length=1);p.hook(q+2,Skip(q+3),length=1);p.hook(q+5,Store(q+6),length=1);p.hook(q+9,Sm83AddHlRegisterPair('bc',q+10),length=1);p.hook(q+10,Sm83IncRegister('d',q+11),length=1);p.hook(q+11,Sm83DecRegister('e',q+12),length=1);p.hook(q+14,Restore(q+17),length=3);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for j in range(7):s.globals[f'write{j}']=i['writes'][55-j*8:48-j*8]
 s.globals['index']=0;s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');return [E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[f'write{j}'] for j in range(7))),constraints=tuple(x.solver.constraints)) for x in collect_returns(p,s,RETURN)]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_draw_trainer_pic_column');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i['writes']);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,7),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('trainer_pic_column');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'DrawTrainerPicColumn');assert linked_bytes(ROM,l,18)==bytes.fromhex('e5d5c51e077201140009141d20f7c1d1e1c9')
