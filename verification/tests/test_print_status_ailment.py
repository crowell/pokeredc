from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83BitRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff
def addresses(i):return (claripy.Concat(i['d'],i['e']),claripy.Concat(i['h'],i['l']),claripy.Concat(i['h'],i['l'])+1,claripy.Concat(i['h'],i['l'])+2)
def alias_constraints(i):
 a=addresses(i);return tuple(claripy.Or(a[x]!=a[y],i[f'memory{x}']==i[f'memory{y}']) for x in range(4) for y in range(x))
class Read(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  a=self.state.globals['addresses'];m=self.state.globals['memory'];target=self.state.regs.de;value=m[0]
  for x in range(1,4):value=claripy.If(a[x]==target,m[x],value)
  self.state.regs.a=value;self.jump(self.n)  # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,n,inc=False,value=None):super().__init__();self.n=n;self.inc=inc;self.value=value
 def run(self):
  value=self.state.regs.a if self.value is None else claripy.BVV(self.value,8);a=self.state.globals['addresses'];m=self.state.globals['memory'];target=self.state.regs.hl;self.state.globals['memory']=[claripy.If(a[x]==target,value,m[x]) for x in range(4)]
  if self.inc:self.state.regs.hl=target+1
  self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for x in range(4):i[f'memory{x}']=claripy.BVS(f'{p}_memory{x}',8)
 return i
def assembly(i):
 l=symbol_location(SYMBOLS,'PrintStatusAilment');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q,Read(q+1),length=1)
 for o,bit in ((1,3),(5,4),(9,5),(13,6)):p.hook(q+o,Sm83BitRegister(bit,'a',q+o+2),length=2)
 p.hook(q+17,Sm83AndImmediate(7,q+19),length=2)
 for first in (20,29,38,47,56):p.hook(q+first+2,Store(q+first+3,True),length=1);p.hook(q+first+5,Store(q+first+6,True),length=1)
 for o,v in ((26,0x8f),(35,0x8d),(44,0x8d),(53,0x99),(62,0x91)):p.hook(q+o,Store(q+o+2,value=v),length=2)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.globals['addresses']=addresses(i);s.globals['memory']=[i[f'memory{x}'] for x in range(4)];s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');return [E(**assembly_registers(x),memory=claripy.Concat(*x.globals['memory']),constraints=alias_constraints(i)+tuple(x.solver.constraints)) for x in collect_returns(p,s,RETURN)]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_print_status_ailment');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[f'memory{x}'] for x in range(4))));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,4),constraints=alias_constraints(i)+tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('status_ailment');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'PrintStatusAilment');assert linked_bytes(ROM,l,65)==bytes.fromhex('1acb5f2018cb67201dcb6f2022cb772027e607c83e92223e8b22368fc93e8f223e9222368dc93e81223e9122368dc93e85223e91223699c93e8f223e80223691c9')
