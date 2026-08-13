from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AddRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff;DONE=0xefff
KEYS=('fetched_low','fetched_high','saved_h','saved_l','saved_d','saved_e','saved_b','saved_c')
class Save(angr.SimProcedure):
 def __init__(self,n,pair):super().__init__();self.n=n;self.pair=pair
 def run(self):
  for r in self.pair:self.state.globals['saved_'+r]=getattr(self.state.regs,r)
  self.jump(self.n)  # type: ignore[override]
class Restore(angr.SimProcedure):
 def __init__(self,n,pair):super().__init__();self.n=n;self.pair=pair
 def run(self):
  for r in self.pair:setattr(self.state.regs,r,self.state.globals['saved_'+r])
  self.jump(self.n)  # type: ignore[override]
class FetchLow(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=self.state.globals['fetched_low'];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
class FetchHigh(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.h=self.state.globals['fetched_high'];self.jump(self.n)  # type: ignore[override]
class Bound(angr.SimProcedure):
 def run(self):self.jump(DONE)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 return i
def project():
 l=symbol_location(SYMBOLS,'CallFunctionInTable');return l,angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
def setup(s,i):
 set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
def endpoint(x):return E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[k] for k in KEYS)),constraints=tuple(x.solver.constraints))
def begin(i):
 l,p=project();q=l.address;p.hook(q,Save(q+1,'hl'),length=1);p.hook(q+1,Save(q+2,'de'),length=1);p.hook(q+2,Save(q+3,'bc'),length=1);p.hook(q+3,Sm83AddRegister('a',q+4),length=1);p.hook(q+7,Sm83AddHlRegisterPair('de',q+8),length=1);p.hook(q+8,FetchLow(q+9),length=1);p.hook(q+9,FetchHigh(q+10),length=1);p.hook(q+15,Bound(),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=DONE);return [endpoint(m.found[0])]
def ret(i):
 l,p=project();q=l.address;p.hook(q+16,Restore(q+17,'bc'),length=1);p.hook(q+17,Restore(q+18,'de'),length=1);p.hook(q+18,Restore(q+19,'hl'),length=1);s=p.factory.blank_state(addr=q+16);setup(s,i);return [endpoint(x) for x in collect_returns(p,s,RETURN)]
def native(symbol,i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(symbol);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('asm,symbol',((begin,'port_call_function_in_table_begin'),(ret,'port_call_function_in_table_return')))
def test_equivalence(asm,symbol):
 i=inputs(symbol);assert_pathwise_equivalent(asm(i),native(symbol,i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'CallFunctionInTable');assert linked_bytes(ROM,l,20)==bytes.fromhex('e5d5c58716005f192a666f11a73dd5e9c1d1e1c9')
