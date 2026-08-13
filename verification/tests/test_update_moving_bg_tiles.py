from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83CpImmediate,Sm83DecRegister,Sm83IncRegister,Sm83Rlca,Sm83Rrca
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000
RIGHT=0xeff8;LEFT=0xeff9;FLOWER=0xeffa;LOOP=0xeffb;REPEAT=0xeffc;DONE=0xeffd;RETURN=0xeffe
NAMES=('tile_animations','counter1','counter2','left','fetched','written','write_h','write_l')
class Load(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)
class Store(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.jump(self.n)
class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
class SetBoundary(Boundary):
 def __init__(self,key,value,n):super().__init__(n);self.key=key;self.value=value
 def run(self):self.state.globals[self.key]=claripy.BVV(self.value,8);self.jump(self.n)
class BranchFlag(angr.SimProcedure):
 def __init__(self,mask,taken,n):super().__init__();self.mask=mask;self.taken=taken;self.n=n
 def run(self):
  self.inhibit_autoret=True;self.successors.add_successor(self.state.copy(),self.taken,(self.state.regs.f&self.mask)!=0,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.n,(self.state.regs.f&self.mask)==0,'Ijk_Boring')
class ZeroA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=0;self.state.regs.f=0x40;self.jump(self.n)
class LoopLoad(angr.SimProcedure):
 def __init__(self,n,hli=False):super().__init__();self.n=n;self.hli=hli
 def run(self):
  if self.state.globals.get('entered',False):self.jump(REPEAT)
  else:
   self.state.globals['entered']=True;self.state.regs.a=self.state.globals['fetched']
   if self.hli:self.state.regs.hl=self.state.regs.hl+1
   self.jump(self.n)
class WriteHli(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['written']=self.state.regs.a;self.state.globals['write_h']=self.state.regs.h;self.state.globals['write_l']=self.state.regs.l;self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
class WriteDe(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['written']=self.state.regs.a;self.state.globals['write_h']=self.state.regs.d;self.state.globals['write_l']=self.state.regs.e;self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'UpdateMovingBgTiles');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
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
 p,q=project();p.hook(q,Load('tile_animations',q+2),length=2);p.hook(q+2,Sm83AndImmediate(0xff,q+3),length=1);p.hook(q+3,BranchFlag(0x40,RETURN,q+4),length=1);p.hook(q+4,Load('counter1',q+6),length=2);p.hook(q+6,Sm83IncRegister('a',q+7),length=1);p.hook(q+7,Store('counter1',q+9),length=2);p.hook(q+9,Sm83CpImmediate(20,q+11),length=2);p.hook(q+11,BranchFlag(1,RETURN,q+12),length=1);p.hook(q+12,Sm83CpImmediate(21,q+14),length=2);p.hook(q+21,Load('counter2',q+24),length=3);p.hook(q+24,Sm83IncRegister('a',q+25),length=1);p.hook(q+25,Sm83AndImmediate(7,q+27),length=2);p.hook(q+27,Store('counter2',q+30),length=3);p.hook(q+30,Sm83AndImmediate(4,q+32),length=2);p.hook(q+34,SetBoundary('left',0,RIGHT),length=1);p.hook(q+42,SetBoundary('left',1,LEFT),length=1);p.hook(q+56,Boundary(FLOWER),length=1);s=p.factory.blank_state(addr=q);setup(s,i);ends=collect(p.factory.simulation_manager(s),{RETURN,RIGHT,LEFT,FLOWER});codes={RETURN:0,RIGHT:1,LEFT:2,FLOWER:3};return [ep(x,codes[x.addr]) for x in ends]
def water_path(i,left):
 p,q=project();start=q+(42 if left else 34);p.hook(start,LoopLoad(start+1),length=1);p.hook(start+1,(Sm83Rlca(start+2) if left else Sm83Rrca(start+2)),length=1);p.hook(start+2,WriteHli(start+3),length=1);p.hook(start+3,Sm83DecRegister('c',start+4),length=1);p.hook(q+48,Boundary(DONE),length=2);s=p.factory.blank_state(addr=start);setup(s,i);s.solver.add(i['left']!=0 if left else i['left']==0);return collect(p.factory.simulation_manager(s),{REPEAT,DONE})
def assembly_water(i):
 ends=water_path(i,False)+water_path(i,True);return [ep(x,1 if x.addr==REPEAT else 0) for x in ends]
def assembly_done(i):
 p,q=project();p.hook(q+48,Load('tile_animations',q+50),length=2);p.hook(q+50,Sm83Rrca(q+51),length=1);p.hook(q+51,BranchFlag(1,q+52,RETURN),length=1);p.hook(q+52,ZeroA(q+53),length=1);p.hook(q+53,Store('counter1',q+55),length=2);p.hook(q+55,Boundary(RETURN),length=1);s=p.factory.blank_state(addr=q+48);setup(s,i);ends=collect(p.factory.simulation_manager(s),{RETURN});return [ep(x,0) for x in ends]
def assembly_flower_setup(i):
 p,q=project();p.hook(q+56,ZeroA(q+57),length=1);p.hook(q+57,Store('counter1',q+59),length=2);p.hook(q+59,Load('counter2',q+62),length=3);p.hook(q+62,Sm83AndImmediate(3,q+64),length=2);p.hook(q+64,Sm83CpImmediate(2,q+66),length=2);p.hook(q+84,Boundary(LOOP),length=1);s=p.factory.blank_state(addr=q+56);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=LOOP);return [ep(x,1) for x in m.found]
def assembly_flower_step(i):
 p,q=project();p.hook(q+84,LoopLoad(q+85,True),length=1);p.hook(q+85,WriteDe(q+86),length=1);p.hook(q+87,Sm83DecRegister('c',q+88),length=1);p.hook(q+90,Boundary(DONE),length=1);s=p.factory.blank_state(addr=q+84);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,DONE});return [ep(x,1 if x.addr==REPEAT else 0) for x in ends]
def native(name,i,returns):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=(x.regs.rax[7:0] if returns else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
CASES=((assembly_setup,'port_update_moving_bg_tiles_setup',True),(assembly_water,'port_update_moving_bg_tiles_water_step',True),(assembly_done,'port_update_moving_bg_tiles_water_done',False),(assembly_flower_setup,'port_update_moving_bg_tiles_flower_setup',True),(assembly_flower_step,'port_update_moving_bg_tiles_flower_step',True))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('assembly,name,returns',CASES)
def test_equivalence(assembly,name,returns):
 i=inputs(name);assert_pathwise_equivalent(assembly(i),native(name,i,returns),(*REGISTERS,'memory','continuation'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'UpdateMovingBgTiles');assert linked_bytes(ROM,l,91)==bytes.fromhex('f0d7a7c8f0d83ce0d8fe14d8fe1528282140910e10fa85d03ce607ea85d0e60420087e0f220d20fa18067e07220d20faf0d70fd0afe0d8c9afe0d8fa85d0e603fe0221191f380821291f280321391f1130900e102a12130d20fac9')
