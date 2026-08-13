from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate,Sm83CpRegister,Sm83IncRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;CONT=0xeffc;TERMINATED=0xeffd;INNER=0xeffe;DONE=0xefff
KEYS=('fetched_outer','fetched_inner','written','did_write')
class Bound(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)  # type: ignore[override]
class RetZ(angr.SimProcedure):
 def __init__(self,n,target):super().__init__();self.n=n;self.target=target
 def run(self):
  self.inhibit_autoret=True;self.successors.add_successor(self.state.copy(),self.target,(self.state.regs.f&0x40)!=0,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.n,(self.state.regs.f&0x40)==0,'Ijk_Boring')  # type: ignore[override]
class Load(angr.SimProcedure):
 def __init__(self,n,key,inc=False,start=False):super().__init__();self.n=n;self.key=key;self.inc=inc;self.start=start
 def run(self):
  if self.start and self.state.globals.get('entered',False):self.jump(CONT);return
  if self.start:self.state.globals['entered']=True
  self.state.regs.a=self.state.globals[self.key];self.state.regs.de=self.state.regs.de+(1 if self.inc else 0);self.jump(self.n)  # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['written']=self.state.regs.a;self.state.globals['did_write']=claripy.BVV(1,8);self.jump(self.n)  # type: ignore[override]
class XorA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=0;self.state.regs.f=0x40;self.jump(self.n)  # type: ignore[override]
class IncDE(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.de=self.state.regs.de+1;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in KEYS:i[n]=claripy.BVS(f'{p}_{n}',8)
 return i
def project():
 l=symbol_location(SYMBOLS,'ZeroOutDuplicatesInList');return l,angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
def setup(s,i):
 set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
def mem(x,i):return claripy.Concat(i['fetched_outer'],i['fetched_inner'],x.globals.get('written',i['written']),x.globals.get('did_write',i['did_write']))
def ep(x,i,r=0):return E(**assembly_registers(x),memory=mem(x,i),result=claripy.BVV(r,8),constraints=tuple(x.solver.constraints))
def begin(i):
 l,p=project();p.hook(l.address+3,Bound(DONE),length=1);s=p.factory.blank_state(addr=l.address);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=DONE);return [ep(m.found[0],i)]
def outer(i):
 l,p=project();q=l.address+3;p.hook(q,Load(q+1,'fetched_outer'),length=1);p.hook(q+1,IncDE(q+2),length=1);p.hook(q+2,Sm83CpImmediate(0xff,q+4),length=2);p.hook(q+4,RetZ(q+5,TERMINATED),length=1);p.hook(q+8,Bound(INNER),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=lambda x:x.addr in {TERMINATED,INNER},num_find=2);return [ep(x,i,1 if x.addr==TERMINATED else 0) for x in m.found]
def inner(i):
 l,p=project();q=l.address+11;outer_addr=l.address+3;p.hook(q,Load(q+1,'fetched_inner',start=True),length=1);p.hook(q+1,Sm83CpImmediate(0xff,q+3),length=2);p.hook(outer_addr,Bound(TERMINATED),length=1);p.hook(q+5,Sm83CpRegister('c',q+6),length=1);p.hook(q+8,XorA(q+9),length=1);p.hook(q+9,Store(q+10),length=1);s=p.factory.blank_state(addr=q);setup(s,i);s.globals['did_write']=claripy.BVV(0,8);m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {CONT,TERMINATED})
  if m.active:m.step()
 return [ep(x,i,1 if x.addr==TERMINATED else 0) for x in m.found]
def native(sym,i,returns=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,4),result=x.regs.rax[7:0] if returns else claripy.BVV(0,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('part,asm,c,ret',[('begin',begin,'port_zero_out_duplicates_begin',False),('outer',outer,'port_zero_out_duplicates_outer_step',True),('inner',inner,'port_zero_out_duplicates_inner_step',True)])
def test_equivalence(part,asm,c,ret):
 i=inputs('dupes_'+part);assert_pathwise_equivalent(asm(i),native(c,i,ret),(*REGISTERS,'memory','result'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'ZeroOutDuplicatesInList');assert linked_bytes(ROM,l,24)==bytes.fromhex('11e9ce1a13feffc84f6b627efeff28f3b92002af772318f3')
