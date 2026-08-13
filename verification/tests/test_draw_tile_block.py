from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AndImmediate,Sm83DecRegister,Sm83SwapRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000
ROW=0xeffb;REPEAT=0xeffc;DONE=0xeffd
NAMES=('blocks_low','blocks_high')+tuple(f'{p}{i}' for p in ('fetched','written','write_h','write_l') for i in range(4))+('saved_h','saved_l')
class Load(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)
class SaveHl(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['saved_h']=self.state.regs.h;self.state.globals['saved_l']=self.state.regs.l;self.jump(self.n)
class RestoreHl(SaveHl):
 def run(self):self.state.regs.h=self.state.globals['saved_h'];self.state.regs.l=self.state.globals['saved_l'];self.jump(self.n)
class SaveBc(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['saved_b']=self.state.regs.b;self.state.globals['saved_c']=self.state.regs.c;self.jump(self.n)
class RestoreBc(SaveBc):
 def run(self):self.state.regs.b=self.state.globals['saved_b'];self.state.regs.c=self.state.globals['saved_c'];self.jump(self.n)
class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
class LoopLoad(angr.SimProcedure):
 def __init__(self,index,n):super().__init__();self.index=index;self.n=n
 def run(self):
  if self.index==0 and self.state.globals.get('entered',False):self.jump(REPEAT);return
  self.state.globals['entered']=True;self.state.regs.a=self.state.globals[f'fetched{self.index}'];self.jump(self.n)
class WriteTile(angr.SimProcedure):
 def __init__(self,index,n,hli):super().__init__();self.index=index;self.n=n;self.hli=hli
 def run(self):
  self.state.globals[f'written{self.index}']=self.state.regs.a;self.state.globals[f'write_h{self.index}']=self.state.regs.h;self.state.globals[f'write_l{self.index}']=self.state.regs.l
  if self.hli:self.state.regs.hl=self.state.regs.hl+1
  self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'DrawTileBlock');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
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
 p,q=project();p.hook(q,SaveHl(q+1),length=1);p.hook(q+1,Load('blocks_low',q+4),length=3);p.hook(q+5,Load('blocks_high',q+8),length=3);p.hook(q+10,Sm83SwapRegister('a',q+12),length=2);p.hook(q+13,Sm83AndImmediate(0xf0,q+15),length=2);p.hook(q+17,Sm83AndImmediate(0x0f,q+19),length=2);p.hook(q+20,Sm83AddHlRegisterPair('bc',q+21),length=1);p.hook(q+23,RestoreHl(q+24),length=1);p.hook(q+26,Boundary(ROW),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=ROW);return [ep(x,1) for x in m.found]
def assembly_row(i):
 p,q=project();p.hook(q+26,SaveBc(q+27),length=1)
 for index,off in enumerate((27,30,33,36)):
  p.hook(q+off,LoopLoad(index,q+off+1),length=1);p.hook(q+off+1,WriteTile(index,q+off+2,index<3),length=1)
 p.hook(q+42,Sm83AddHlRegisterPair('bc',q+43),length=1);p.hook(q+43,RestoreBc(q+44),length=1);p.hook(q+44,Sm83DecRegister('c',q+45),length=1);p.hook(q+47,Boundary(DONE),length=1);s=p.factory.blank_state(addr=q+26);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,DONE});return [ep(x,1 if x.addr==REPEAT else 0) for x in ends]
def native(name,i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=x.regs.rax[7:0],constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('assembly,name',((assembly_setup,'port_draw_tile_block_setup'),(assembly_row,'port_draw_tile_block_row_step')))
def test_equivalence(assembly,name):
 i=inputs(name);assert_pathwise_equivalent(assembly(i),native(name,i),(*REGISTERS,'memory','continuation'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'DrawTileBlock');assert linked_bytes(ROM,l,48)==bytes.fromhex('e5fa2cd56ffa2dd56779cb3747e6f04f78e60f4709545de10e04c51a22131a22131a22131a771301150009c10d20ebc9')
