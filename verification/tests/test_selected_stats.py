from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddRegister,Sm83AndImmediate,Sm83CpImmediate,Sm83DecRegister,Sm83RlRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff;CONT=0xeffe
KEYS=('whose_turn','player_mask','enemy_mask','stat_high','stat_low')
class Fetch(angr.SimProcedure):
 def __init__(self,n,key,register='a'):super().__init__();self.n=n;self.key=key;self.register=register
 def run(self):setattr(self.state.regs,self.register,self.state.globals[self.key]);self.jump(self.n)  # type: ignore[override]
class StartSrl(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(CONT);return
  self.state.globals['entered']=True;v=self.state.regs.b;r=claripy.LShR(v,1);self.state.regs.b=r;self.state.regs.f=claripy.If(r==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.ZeroExt(7,v[0]);self.jump(self.n)  # type: ignore[override]
class MoveHl(angr.SimProcedure):
 def __init__(self,n,delta):super().__init__();self.n=n;self.delta=delta
 def run(self):self.state.regs.hl=self.state.regs.hl+self.delta;self.jump(self.n)  # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,n,key,delta=0):super().__init__();self.n=n;self.key=key;self.delta=delta
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.state.regs.hl=self.state.regs.hl+self.delta;self.jump(self.n)  # type: ignore[override]
class RrLow(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  v=self.state.globals['stat_low'];r=claripy.Concat(self.state.regs.f[0],v[7:1]);self.state.globals['stat_low']=r;self.state.regs.f=claripy.If(r==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.ZeroExt(7,v[0]);self.jump(self.n)  # type: ignore[override]
class OrLow(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  self.state.regs.a=self.state.regs.a|self.state.globals['stat_low'];self.state.regs.f=claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8));self.jump(self.n)  # type: ignore[override]
class StoreOne(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['stat_low']=claripy.BVV(1,8);self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 return i
def project(symbol):
 l=symbol_location(SYMBOLS,symbol);return l,angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
def setup(s,i):
 set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
def memory(x):return claripy.Concat(*(x.globals[k] for k in KEYS))
def endpoint(x,result):return E(**assembly_registers(x),memory=memory(x),result=claripy.BVV(result,8),constraints=tuple(x.solver.constraints))
def init_assembly(symbol,i):
 l,p=project(symbol);q=l.address;halve=symbol.startswith('Halve')
 p.hook(q,Fetch(q+2,'whose_turn'),length=2);p.hook(q+2,Sm83AndImmediate(0xff,q+3),length=1);p.hook(q+3,Fetch(q+6,'player_mask'),length=3);p.hook(q+11,Fetch(q+14,'enemy_mask'),length=3)
 s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=q+20,num_find=2);assert len(m.found)==2;return [endpoint(x,0) for x in m.found]
def step_assembly(symbol,i):
 l,p=project(symbol);q=l.address;halve=symbol.startswith('Halve')
 p.hook(q+20,StartSrl(q+22),length=2);p.hook(q+25,MoveHl(q+26,1),length=1);p.hook(q+26,MoveHl(q+27,1),length=1);p.hook(q+27,Sm83DecRegister('c',q+28),length=1)
 if halve:
  p.hook(q+31,Fetch(q+32,'stat_high'),length=1);from verification.harness.sm83_shims import Sm83SrlRegister;p.hook(q+32,Sm83SrlRegister('a',q+34),length=2);p.hook(q+34,Store(q+35,'stat_high',1),length=1);p.hook(q+35,RrLow(q+37),length=2);p.hook(q+37,OrLow(q+38),length=1);p.hook(q+40,StoreOne(q+42),length=2);p.hook(q+42,MoveHl(q+43,-1),length=1)
 else:
  p.hook(q+31,Fetch(q+32,'stat_low'),length=1);p.hook(q+32,Sm83AddRegister('a',q+33),length=1);p.hook(q+33,Store(q+34,'stat_low',-1),length=1);p.hook(q+34,Fetch(q+35,'stat_high'),length=1);p.hook(q+35,Sm83RlRegister('a',q+37),length=2);p.hook(q+37,Store(q+38,'stat_high',1),length=1)
 s=p.factory.blank_state(addr=q+20);setup(s,i);m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {CONT,RETURN})
  if m.active:m.step()
 return [endpoint(x,0 if x.addr==CONT else 1) for x in m.found]
def native(symbol,i,returns):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(symbol);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),result=x.regs.rax[7:0] if returns else claripy.BVV(0,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('routine',('DoubleSelectedStats','HalveSelectedStats'))
@pytest.mark.parametrize('part',('begin','step'))
def test_equivalence(routine,part):
 i=inputs(f'{routine}_{part}');asm=init_assembly(routine,i) if part=='begin' else step_assembly(routine,i);symbol=f'port_{routine.removesuffix("SelectedStats").lower()}_selected_stats_{part}';assert_pathwise_equivalent(asm,native(symbol,i,part=='step'),(*REGISTERS,'memory','result'))
def test_exact_bodies():
 l=symbol_location(SYMBOLS,'DoubleSelectedStats');assert linked_bytes(ROM,l,39)==bytes.fromhex('f0f3a7fa60d02126d02806fa65d021f7cf0e0447cb38dc9f5623230dc818f57e87327ecb1722c9')
 l=symbol_location(SYMBOLS,'HalveSelectedStats');assert linked_bytes(ROM,l,44)==bytes.fromhex('f0f3a7fa61d02125d02806fa66d021f6cf0e0447cb38dcc65623230dc818f57ecb3f22cb1eb6200236012bc9')
