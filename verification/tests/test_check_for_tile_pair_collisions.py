from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83CpImmediate,Sm83CpRegister,Sm83Scf
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000
LOOP=0xeffc;REPEAT=0xeffd;NO_MATCH=0xeffe;COLLISION=0xefff
NAMES=('front_tile','current_tileset','standing_tile','entry_tileset','first_tile','second_tile')
class Load(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)
class LoadHli(Load):
 def run(self):self.state.regs.a=self.state.globals[self.key];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
class LoopEntry(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(REPEAT)
  else:
   self.state.globals['entered']=True;self.state.regs.a=self.state.globals['current_tileset'];self.state.regs.b=self.state.regs.a;self.state.regs.a=self.state.globals['entry_tileset'];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'CheckForTilePairCollisions');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
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
 p,q=project();p.hook(q,Load('front_tile',q+3),length=3);p.hook(q+4,Boundary(LOOP),length=5);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=LOOP);return [ep(x,1) for x in m.found]
def assembly_step(i):
 p,q=project();p.hook(q+4,LoopEntry(q+9),length=5);p.hook(q+9,Sm83CpImmediate(0xff,q+11),length=2);p.hook(q+13,Sm83CpRegister('b',q+14),length=1);p.hook(q+20,Load('standing_tile',q+23),length=3);p.hook(q+24,Load('first_tile',q+25),length=1);p.hook(q+25,Sm83CpRegister('b',q+26),length=1);p.hook(q+29,Load('second_tile',q+30),length=1);p.hook(q+30,Sm83CpRegister('b',q+31),length=1);p.hook(q+36,Load('second_tile',q+37),length=1);p.hook(q+37,Sm83CpRegister('c',q+38),length=1);p.hook(q+43,LoadHli('first_tile',q+44),length=1);p.hook(q+44,Sm83CpRegister('c',q+45),length=1);p.hook(q+48,Sm83Scf(q+49),length=1);p.hook(q+49,Boundary(COLLISION),length=1);p.hook(q+50,Sm83AndImmediate(0xff,q+51),length=1);p.hook(q+51,Boundary(NO_MATCH),length=1);s=p.factory.blank_state(addr=q+4);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,NO_MATCH,COLLISION});codes={REPEAT:1,NO_MATCH:0,COLLISION:2};return [ep(x,codes[x.addr]) for x in ends]
def native(name,i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=x.regs.rax[7:0],constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('assembly,name',((assembly_setup,'port_check_tile_pair_collisions_setup'),(assembly_step,'port_check_tile_pair_collisions_step')))
def test_equivalence(assembly,name):
 i=inputs(name);assert_pathwise_equivalent(assembly(i),native(name,i),(*REGISTERS,'memory','continuation'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'CheckForTilePairCollisions');assert linked_bytes(ROM,l,52)==bytes.fromhex('fac6cf4ffa67d3472afeff2825b82804232318f0fa0ecf477eb82807237eb8280918ee237eb9280818da2b2ab92320d437c9a7c9')
