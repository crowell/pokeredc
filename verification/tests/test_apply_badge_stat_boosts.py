from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AdcRegister,Sm83AddRegister,Sm83CpImmediate,Sm83DecRegister,Sm83IncRegister,Sm83RrRegister,Sm83SbcImmediate,Sm83SrlRegister,Sm83SubImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000
BOOST=0xeff7;ADVANCE=0xeff8;LOOP=0xeff9;REPEAT=0xeffa;DONE=0xeffb;RETURN=0xeffc;HELPER_RETURN=0xeffd
NAMES=('link_state','badges','stat_high','stat_low')
class Load(angr.SimProcedure):
 def __init__(self,key,n,delta=0):super().__init__();self.key=key;self.n=n;self.delta=delta
 def run(self):self.state.regs.a=self.state.globals[self.key];self.state.regs.hl=self.state.regs.hl+self.delta;self.jump(self.n)
class LoadHli(Load):
 def run(self):self.state.regs.a=self.state.globals[self.key];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
class LoadRegister(Load):
 def __init__(self,reg,key,n):super().__init__(key,n);self.reg=reg
 def run(self):setattr(self.state.regs,self.reg,self.state.globals[self.key]);self.jump(self.n)
class Store(angr.SimProcedure):
 def __init__(self,key,n,delta=0):super().__init__();self.key=key;self.n=n;self.delta=delta
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.state.regs.hl=self.state.regs.hl+self.delta;self.jump(self.n)
class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
class BranchC(angr.SimProcedure):
 def __init__(self,taken,n):super().__init__();self.taken=taken;self.n=n
 def run(self):
  self.inhibit_autoret=True;self.successors.add_successor(self.state.copy(),self.taken,(self.state.regs.f&1)!=0,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.n,(self.state.regs.f&1)==0,'Ijk_Boring')
class BranchZ(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  self.inhibit_autoret=True;self.successors.add_successor(self.state.copy(),RETURN,(self.state.regs.f&0x40)!=0,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.n,(self.state.regs.f&0x40)==0,'Ijk_Boring')
class LoopSrl(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(REPEAT)
  else:
   self.state.globals['entered']=True;v=self.state.regs.b;r=claripy.LShR(v,1);self.state.regs.b=r;self.state.regs.f=claripy.If(r==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.ZeroExt(7,v[0]);self.jump(self.n)
class CallHelper(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  # Compose with the independently proved helper by copying its native endpoint.
  self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'ApplyBadgeStatBoosts');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
def setup(s,i):
 set_assembly_registers(s,i)
 for n in NAMES:s.globals[n]=i[n]
def ep(x,c):return E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[n] for n in NAMES)),continuation=claripy.BVV(c,8),constraints=tuple(x.solver.constraints))
def collect(m,targets):
 m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in targets)
  if m.active:m.step()
 return m.found
def assembly_setup(i):
 p,q=project();p.hook(q,Load('link_state',q+3),length=3);p.hook(q+3,Sm83CpImmediate(4,q+5),length=2);p.hook(q+5,BranchZ(q+6),length=1);p.hook(q+6,Load('badges',q+9),length=3);p.hook(q+15,Boundary(LOOP),length=2);s=p.factory.blank_state(addr=q);setup(s,i);ends=collect(p.factory.simulation_manager(s),{RETURN,LOOP});return [ep(x,0 if x.addr==RETURN else 1) for x in ends]
def assembly_helper(i):
 p,q=project();start=q+28;p.hook(start,LoadHli('stat_high',start+1),length=1);p.hook(start+2,LoadRegister('e','stat_low',start+3),length=1)
 for off,proc in ((31,Sm83SrlRegister('d',start+5)),(33,Sm83RrRegister('e',start+7)),(35,Sm83SrlRegister('d',start+9)),(37,Sm83RrRegister('e',start+11)),(39,Sm83SrlRegister('d',start+13)),(41,Sm83RrRegister('e',start+15))):p.hook(q+off,proc,length=2)
 p.hook(q+43,Load('stat_low',q+44),length=1);p.hook(q+44,Sm83AddRegister('e',q+45),length=1);p.hook(q+45,Store('stat_low',q+46,-1),length=1);p.hook(q+46,Load('stat_high',q+47),length=1);p.hook(q+47,Sm83AdcRegister('d',q+48),length=1);p.hook(q+48,Store('stat_high',q+49,1),length=1);p.hook(q+49,Load('stat_low',q+50,-1),length=1);p.hook(q+50,Sm83SubImmediate(0xe7,q+52),length=2);p.hook(q+52,Load('stat_high',q+53),length=1);p.hook(q+53,Sm83SbcImmediate(3,q+55),length=2);p.hook(q+55,BranchC(HELPER_RETURN,q+56),length=1);p.hook(q+58,Store('stat_high',q+59,1),length=1);p.hook(q+61,Store('stat_low',q+62,-1),length=1);p.hook(q+62,Boundary(HELPER_RETURN),length=1);s=p.factory.blank_state(addr=start);setup(s,i);ends=collect(p.factory.simulation_manager(s),{HELPER_RETURN});return [ep(x,0) for x in ends]
def assembly_dispatch(i):
 p,q=project();p.hook(q+15,Sm83SrlRegister('b',q+17),length=2);p.hook(q+17,BranchC(BOOST,ADVANCE),length=3);s=p.factory.blank_state(addr=q+15);setup(s,i);ends=collect(p.factory.simulation_manager(s),{BOOST,ADVANCE});return [ep(x,1 if x.addr==BOOST else 0) for x in ends]
def assembly_advance(i):
 p,q=project();p.hook(q+22,Sm83SrlRegister('b',q+24),length=2);p.hook(q+24,Sm83DecRegister('c',q+25),length=1);p.hook(q+15,Boundary(REPEAT),length=2);p.hook(q+27,Boundary(DONE),length=1);s=p.factory.blank_state(addr=q+20);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,DONE});return [ep(x,1 if x.addr==REPEAT else 0) for x in ends]
def native(name,i,returns,constant):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=(x.regs.rax[7:0] if returns else claripy.BVV(constant,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('assembly,name,returns,constant',((assembly_setup,'port_apply_badge_stat_boosts_setup',True,0),(assembly_helper,'port_apply_badge_boost_to_stat',False,0),(assembly_dispatch,'port_apply_badge_stat_boosts_dispatch',True,0),(assembly_advance,'port_apply_badge_stat_boosts_advance',True,0)))
def test_equivalence(assembly,name,returns,constant):
 i=inputs(name);assert_pathwise_equivalent(assembly(i),native(name,i,returns,constant),(*REGISTERS,'memory','continuation'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'ApplyBadgeStatBoosts');assert linked_bytes(ROM,l,63)==bytes.fromhex('fa2bd1fe04c8fa56d3472125d00e04cb38dc356e2323cb380d20f4c92a575ecb3acb1bcb3acb1bcb3acb1b7e83327e8a223ad6e77ede03d83e03223ee732c9')
