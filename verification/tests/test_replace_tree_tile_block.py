from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AddImmediate,Sm83AndImmediate,Sm83CpImmediate,Sm83CpRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000
SCAN=0xeffb;REPEAT=0xeffc;SENTINEL=0xeffd;FOUND=0xeffe
NAMES=('map_width','map_pointer_low','map_pointer_high','facing','x_block','y_block','target_tile','fetched_match','replacement','written','write_h','write_l')
class Load(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)
class LoadHli(Load):
 def run(self):self.state.regs.a=self.state.globals[self.key];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
class LoadRegister(Load):
 def __init__(self,reg,key,n):super().__init__(key,n);self.reg=reg
 def run(self):setattr(self.state.regs,self.reg,self.state.globals[self.key]);self.jump(self.n)
class SaveDe(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['saved_d']=self.state.regs.d;self.state.globals['saved_e']=self.state.regs.e;self.jump(self.n)
class RestoreDe(SaveDe):
 def run(self):self.state.regs.d=self.state.globals['saved_d'];self.state.regs.e=self.state.globals['saved_e'];self.jump(self.n)
class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
class BranchZ(angr.SimProcedure):
 def __init__(self,taken,n):super().__init__();self.taken=taken;self.n=n
 def run(self):
  self.inhibit_autoret=True;self.successors.add_successor(self.state.copy(),self.taken,(self.state.regs.f&0x40)!=0,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.n,(self.state.regs.f&0x40)==0,'Ijk_Boring')
class LoopLoad(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(REPEAT)
  else:self.state.globals['entered']=True;self.state.regs.a=self.state.globals['fetched_match'];self.jump(self.n)
class StoreReplacement(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['target_tile']=self.state.regs.a;self.state.globals['written']=self.state.regs.a;self.state.globals['write_h']=self.state.regs.h;self.state.globals['write_l']=self.state.regs.l;self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'ReplaceTreeTileBlock');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
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
 p,q=project();p.hook(q,SaveDe(q+1),length=1);p.hook(q+1,Load('map_width',q+4),length=3);p.hook(q+4,Sm83AddImmediate(6,q+6),length=2);p.hook(q+14,LoadHli('map_pointer_low',q+15),length=1);p.hook(q+15,LoadRegister('h','map_pointer_high',q+16),length=1);p.hook(q+17,Sm83AddHlRegisterPair('bc',q+18),length=1);p.hook(q+18,Load('facing',q+21),length=3);p.hook(q+21,Sm83AndImmediate(0xff,q+22),length=1);p.hook(q+24,Sm83CpImmediate(4,q+26),length=2);p.hook(q+28,Sm83CpImmediate(8,q+30),length=2)
 for off,key,n in ((32,'x_block',35),(40,'y_block',43),(48,'y_block',51),(56,'x_block',59)):p.hook(q+off,Load(key,q+n),length=3);p.hook(q+n,Sm83AndImmediate(0xff,q+n+1),length=1)
 for off,pair in ((64,'bc'),(65,'bc'),(68,'de'),(73,'bc'),(74,'de'),(79,'bc'),(80,'de')):p.hook(q+off,Sm83AddHlRegisterPair(pair,q+off+1),length=1)
 p.hook(q+81,RestoreDe(q+82),length=1);p.hook(q+82,Load('target_tile',q+83),length=1);p.hook(q+84,Boundary(SCAN),length=1);s=p.factory.blank_state(addr=q);setup(s,i);ends=collect(p.factory.simulation_manager(s),{SCAN});return [ep(x,1) for x in ends]
def assembly_scan(i):
 p,q=project();p.hook(q+84,LoopLoad(q+85),length=1);p.hook(q+87,Sm83CpImmediate(0xff,q+89),length=2);p.hook(q+89,BranchZ(SENTINEL,q+90),length=1);p.hook(q+90,Sm83CpRegister('c',q+91),length=1);p.hook(q+94,Load('replacement',q+95),length=1);p.hook(q+95,StoreReplacement(q+96),length=1);p.hook(q+96,Boundary(FOUND),length=1);s=p.factory.blank_state(addr=q+84);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,SENTINEL,FOUND});codes={REPEAT:1,SENTINEL:0,FOUND:2};return [ep(x,codes[x.addr]) for x in ends]
def native(name,i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=x.regs.rax[7:0],constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('assembly,name',((assembly_setup,'port_replace_tree_tile_block_setup'),(assembly_scan,'port_replace_tree_tile_block_scan_step')))
def test_equivalence(assembly,name):
 i=inputs(name);assert_pathwise_equivalent(assembly(i),native(name,i),(*REGISTERS,'memory','continuation'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'ReplaceTreeTileBlock');assert linked_bytes(ROM,l,97)==bytes.fromhex('d5fa69d3c6064f06001600215fd32a666f09fa09c1a72810fe042814fe082818fa64d3a7281b1825fa63d3a728131810fa63d3a7280c1809fa64d3a72809180109091e0219180a1e01091918041e030919d17e4f1a1313feffc8b920f71b1a77c9')
