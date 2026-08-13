from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate,Sm83CpRegister,Sm83IncRegister,Sm83LoadAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;CONT=0xeffc;TERM=0xeffd;MATCH=0xeffe;DONE=0xefff;HY=0xcd40;HX=0xcd41;MAP=0xd35e
KEYS=('hidden_y','hidden_x','current_map','fetched_map','fetched_y','fetched_x')
class Bound(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)  # type: ignore[override]
class RetZ(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):  # type: ignore[override]
  self.inhibit_autoret=True;self.successors.add_successor(self.state.copy(),TERM,(self.state.regs.f&0x40)!=0,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.n,(self.state.regs.f&0x40)==0,'Ijk_Boring')
class StartInc(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):  # type: ignore[override]
  if self.state.globals.get('entered',False):self.jump(CONT);return
  self.state.globals['entered']=True;self.state.regs.c=self.state.regs.c+1;self.jump(self.n)
class Fetch(angr.SimProcedure):
 def __init__(self,n,key,first=False):super().__init__();self.n=n;self.key=key;self.first=first
 def run(self):  # type: ignore[override]
  if self.first and self.state.globals.get('entered',False):self.jump(CONT);return
  if self.first:self.state.globals['entered']=True
  self.state.regs.a=self.state.globals[self.key];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in KEYS:i[n]=claripy.BVS(f'{p}_{n}',8)
 return i
def project():
 l=symbol_location(SYMBOLS,'FindHiddenItemOrCoinsIndex');return l,angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
def setup(s,i):
 set_assembly_registers(s,i);s.memory.store(HY,i['hidden_y']);s.memory.store(HX,i['hidden_x']);s.memory.store(MAP,i['current_map'])
 for k in KEYS[3:]:s.globals[k]=i[k]
def mem(x,i):return claripy.Concat(x.memory.load(HY,1),x.memory.load(HX,1),x.memory.load(MAP,1),i['fetched_map'],i['fetched_y'],i['fetched_x'])
def ep(x,i,r=0):return E(**assembly_registers(x),memory=mem(x,i),result=claripy.BVV(r,8),constraints=tuple(x.solver.constraints))
def begin(i):
 l,p=project();q=l.address;p.hook(q,Sm83LoadAImmediate(HY,q+3),length=3);p.hook(q+4,Sm83LoadAImmediate(HX,q+7),length=3);p.hook(q+8,Sm83LoadAImmediate(MAP,q+11),length=3);p.hook(q+14,Bound(DONE),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=DONE);return [ep(m.found[0],i)]
def step(i):
 l,p=project();q=l.address+14;p.hook(q,StartInc(q+1),length=1);p.hook(q+1,Fetch(q+2,'fetched_map'),length=1);p.hook(q+2,Sm83CpImmediate(0xff,q+4),length=2);p.hook(q+4,RetZ(q+5),length=1);p.hook(q+5,Sm83CpRegister('b',q+6),length=1);p.hook(q+8,Fetch(q+9,'fetched_y'),length=1);p.hook(q+9,Sm83CpRegister('d',q+10),length=1);p.hook(q+12,Fetch(q+13,'fetched_x'),length=1);p.hook(q+13,Sm83CpRegister('e',q+14),length=1);p.hook(q+17,Bound(MATCH),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {CONT,TERM,MATCH})
  if m.active:m.step()
 code={CONT:0,TERM:1,MATCH:2};return [ep(x,i,code[x.addr]) for x in m.found]
def native(sym,i,returns=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,6),result=x.regs.rax[7:0] if returns else claripy.BVV(0,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('part,asm,c,ret',[('begin',begin,'port_find_hidden_item_or_coins_index_begin',False),('step',step,'port_find_hidden_item_or_coins_index_step',True)])
def test_equivalence(part,asm,c,ret):
 i=inputs('hidden_'+part);assert_pathwise_equivalent(asm(i),native(c,i,ret),(*REGISTERS,'memory','result'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'FindHiddenItemOrCoinsIndex');assert linked_bytes(ROM,l,36)==bytes.fromhex('fa40cd57fa41cd5ffa5ed3470eff0c2afeffc8b8200a2aba20072abb20f079c9232318ea')
