from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddImmediate,Sm83AddRegister,Sm83DecRegister,Sm83IncRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;INNER=0xeffc;ROW=0xeffd;FINISH=0xeffe
NAMES=('strip_width','north_south_width','east_west_width','map_width','fetched','written','saved_d','saved_e','saved_h','saved_l')
class Save(angr.SimProcedure):
 def __init__(self,pair,n):super().__init__();self.pair=pair;self.n=n
 def run(self):
  for r in self.pair:self.state.globals['saved_'+r]=getattr(self.state.regs,r)
  self.jump(self.n)
class Restore(angr.SimProcedure):
 def __init__(self,pair,n):super().__init__();self.pair=pair;self.n=n
 def run(self):
  for r in self.pair:setattr(self.state.regs,r,self.state.globals['saved_'+r])
  self.jump(self.n)
class Load(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)
class LoopLoad(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(INNER)
  else:self.state.globals['entered']=True;self.state.regs.a=self.state.globals['fetched'];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
class Store(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['written']=self.state.regs.a;self.jump(self.n)
class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project(sym):
 l=symbol_location(SYMBOLS,sym);p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
def setup(s,i):
 set_assembly_registers(s,i)
 for n in NAMES:s.globals[n]=i[n]
def ep(x,cont):return E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[n] for n in NAMES)),continuation=claripy.BVV(cont,8),constraints=tuple(x.solver.constraints))
def collect(m,targets):
 m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in targets)
  if m.active:m.step()
 return m.found
def north_begin(i):
 p,q=project('LoadNorthSouthConnectionsTileMap');p.hook(q+2,Boundary(ROW),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=ROW);return [ep(x,1) for x in m.found]
def north_row(i):
 p,q=project('LoadNorthSouthConnectionsTileMap');p.hook(q+2,Save('de',q+3),length=1);p.hook(q+3,Save('hl',q+4),length=1);p.hook(q+4,Load('strip_width',q+6),length=2);p.hook(q+7,Boundary(INNER),length=1);s=p.factory.blank_state(addr=q+2);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=INNER);return [ep(x,1) for x in m.found]
def north_inner(i):
 p,q=project('LoadNorthSouthConnectionsTileMap');p.hook(q+7,LoopLoad(q+8),length=1);p.hook(q+8,Store(q+9),length=1);p.hook(q+10,Sm83DecRegister('b',q+11),length=1);p.hook(q+13,Boundary(FINISH),length=1);s=p.factory.blank_state(addr=q+7);setup(s,i);ends=collect(p.factory.simulation_manager(s),{INNER,FINISH});return [ep(x,1 if x.addr==INNER else 0) for x in ends]
def north_finish(i):
 p,q=project('LoadNorthSouthConnectionsTileMap');p.hook(q+13,Restore('hl',q+14),length=1);p.hook(q+14,Restore('de',q+15),length=1);p.hook(q+15,Load('north_south_width',q+17),length=2);p.hook(q+17,Sm83AddRegister('l',q+18),length=1);p.hook(q+21,Sm83IncRegister('h',q+22),length=1);p.hook(q+22,Load('map_width',q+25),length=3);p.hook(q+25,Sm83AddImmediate(6,q+27),length=2);p.hook(q+27,Sm83AddRegister('e',q+28),length=1);p.hook(q+31,Sm83IncRegister('d',q+32),length=1);p.hook(q+32,Sm83DecRegister('c',q+33),length=1);p.hook(q+2,Boundary(ROW),length=1);p.hook(q+35,Boundary(FINISH),length=1);s=p.factory.blank_state(addr=q+13);setup(s,i);ends=collect(p.factory.simulation_manager(s),{ROW,FINISH});return [ep(x,1 if x.addr==ROW else 0) for x in ends]
def east_row(i):
 p,q=project('LoadEastWestConnectionsTileMap');p.hook(q,Save('hl',q+1),length=1);p.hook(q+1,Save('de',q+2),length=1);p.hook(q+4,Boundary(INNER),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=INNER);return [ep(x,1) for x in m.found]
def east_inner(i):
 p,q=project('LoadEastWestConnectionsTileMap');p.hook(q+4,LoopLoad(q+5),length=1);p.hook(q+5,Store(q+6),length=1);p.hook(q+7,Sm83DecRegister('c',q+8),length=1);p.hook(q+10,Boundary(FINISH),length=1);s=p.factory.blank_state(addr=q+4);setup(s,i);ends=collect(p.factory.simulation_manager(s),{INNER,FINISH});return [ep(x,1 if x.addr==INNER else 0) for x in ends]
def east_finish(i):
 p,q=project('LoadEastWestConnectionsTileMap');p.hook(q+10,Restore('de',q+11),length=1);p.hook(q+11,Restore('hl',q+12),length=1);p.hook(q+12,Load('east_west_width',q+14),length=2);p.hook(q+14,Sm83AddRegister('l',q+15),length=1);p.hook(q+18,Sm83IncRegister('h',q+19),length=1);p.hook(q+19,Load('map_width',q+22),length=3);p.hook(q+22,Sm83AddImmediate(6,q+24),length=2);p.hook(q+24,Sm83AddRegister('e',q+25),length=1);p.hook(q+28,Sm83IncRegister('d',q+29),length=1);p.hook(q+29,Sm83DecRegister('b',q+30),length=1);p.hook(q,Boundary(ROW),length=1,replace=True);p.hook(q+32,Boundary(FINISH),length=1);s=p.factory.blank_state(addr=q+10);setup(s,i);ends=collect(p.factory.simulation_manager(s),{ROW,FINISH});return [ep(x,1 if x.addr==ROW else 0) for x in ends]
def native(name,i,returns,constant):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=(x.regs.rax[7:0] if returns else claripy.BVV(constant,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
CASES=((north_begin,'port_load_north_south_connections_begin',False,1),(north_row,'port_load_north_south_connections_row_begin',False,1),(north_inner,'port_load_north_south_connections_inner_step',True,0),(north_finish,'port_load_north_south_connections_row_finish',True,0),(east_row,'port_load_east_west_connections_row_begin',False,1),(east_inner,'port_load_east_west_connections_inner_step',True,0),(east_finish,'port_load_east_west_connections_row_finish',True,0))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('asm,name,returns,constant',CASES)
def test_equivalence(asm,name,returns,constant):
 i=inputs(name);assert_pathwise_equivalent(asm(i),native(name,i,returns,constant),(*REGISTERS,'memory','continuation'))
def test_exact_bodies():
 a=symbol_location(SYMBOLS,'LoadNorthSouthConnectionsTileMap');assert linked_bytes(ROM,a,36)==bytes.fromhex('0e03d5e5f08b472a12130520fae1d1f08c856f300124fa69d3c606835f3001140d20dfc9');b=symbol_location(SYMBOLS,'LoadEastWestConnectionsTileMap');assert linked_bytes(ROM,b,33)==bytes.fromhex('e5d50e032a12130d20fad1e1f08b856f300124fa69d3c606835f3001140520e0c9')
