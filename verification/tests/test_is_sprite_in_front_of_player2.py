from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddImmediate,Sm83AddRegister,Sm83AndImmediate,Sm83CpImmediate,Sm83CpRegister,Sm83DecRegister,Sm83IncRegister,Sm83SubRegister

ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000
LOOP=0xeffc;REPEAT=0xeffd;RETURN=0xeffe;FOUND=0xefff
NAMES=('facing_direction','player_direction','num_sprites','sprite_image','sprite_visibility','sprite_y','sprite_x','movement_status','text_id')

class Load(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)
class LoadHli(Load):
 def run(self):self.state.regs.a=self.state.globals[self.key];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
class Store(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.jump(self.n)
class SplitNum(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  self.inhibit_autoret=True
  self.state.regs.f=claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8))
  self.successors.add_successor(self.state.copy(),RETURN,self.state.regs.a==0,'Ijk_Boring')
  self.successors.add_successor(self.state,self.n,self.state.regs.a!=0,'Ijk_Boring')
class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
class LoopStart(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(REPEAT)
  else:self.state.globals['entered']=True;self.state.globals['saved_hl']=self.state.regs.hl;self.jump(self.n)
class RestoreHl(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.hl=self.state.globals['saved_hl'];self.jump(self.n)
class SetMovement(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['movement_status']|=0x80;self.jump(self.n)

@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'IsSpriteInFrontOfPlayer2');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
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
 p,q=project();p.hook(q+3,Load('facing_direction',q+6),length=3);p.hook(q+6,Sm83CpImmediate(4,q+8),length=2);p.hook(q+11,Sm83SubRegister('d',q+12),length=1);p.hook(q+17,Sm83CpImmediate(0,q+19),length=2);p.hook(q+22,Sm83AddRegister('d',q+23),length=1);p.hook(q+28,Sm83CpImmediate(12,q+30),length=2);p.hook(q+33,Sm83AddRegister('d',q+34),length=1);p.hook(q+40,Sm83SubRegister('d',q+41),length=1);p.hook(q+44,Store('player_direction',q+47),length=3);p.hook(q+47,Load('num_sprites',q+50),length=3);p.hook(q+50,SplitNum(q+52),length=2);p.hook(q+58,Boundary(LOOP),length=1);s=p.factory.blank_state(addr=q);setup(s,i);ends=collect(p.factory.simulation_manager(s),{LOOP,RETURN});return [ep(x,1 if x.addr==LOOP else 0) for x in ends]
def assembly_step(i):
 p,q=project();p.hook(q+58,LoopStart(q+59),length=1);p.hook(q+59,LoadHli('sprite_image',q+60),length=1);p.hook(q+60,Sm83AndImmediate(0xff,q+61),length=1);p.hook(q+64,LoadHli('sprite_visibility',q+65),length=1);p.hook(q+65,Sm83IncRegister('a',q+66),length=1);p.hook(q+69,LoadHli('sprite_y',q+70),length=1);p.hook(q+70,Sm83CpRegister('b',q+71),length=1);p.hook(q+74,Load('sprite_x',q+75),length=1);p.hook(q+75,Sm83CpRegister('c',q+76),length=1);p.hook(q+78,RestoreHl(q+79),length=1);p.hook(q+80,Sm83AddImmediate(16,q+82),length=2);p.hook(q+83,Sm83IncRegister('e',q+84),length=1);p.hook(q+84,Sm83DecRegister('d',q+85),length=1);p.hook(q+87,Boundary(RETURN),length=1);p.hook(q+88,RestoreHl(q+89),length=1);p.hook(q+90,Sm83AndImmediate(0xf0,q+92),length=2);p.hook(q+92,Sm83IncRegister('a',q+93),length=1);p.hook(q+94,SetMovement(q+96),length=2);p.hook(q+97,Store('text_id',q+99),length=2);p.hook(q+99,Boundary(FOUND),length=1);s=p.factory.blank_state(addr=q+58);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,RETURN,FOUND});codes={REPEAT:1,RETURN:0,FOUND:2};return [ep(x,codes[x.addr]) for x in ends]
def native(name,i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=x.regs.rax[7:0],constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('assembly,name',((assembly_setup,'port_is_sprite_in_front_setup'),(assembly_step,'port_is_sprite_in_front_step')))
def test_equivalence(assembly,name):
 i=inputs(name);assert_pathwise_equivalent(assembly(i),native(name,i),(*REGISTERS,'memory','continuation'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'IsSpriteInFrontOfPlayer2');assert linked_bytes(ROM,l,100)==bytes.fromhex('01403cfa09c1fe0420077892473e08181bfe0020077882473e041810fe0c200779824f3e01180579924f3e02ea2ad5fae1d4a7c82110c1571e01e52aa7280f2c2a3c280a2c2ab820052c7eb9280ae17dc6106f1c1520e3c9e17de6f03c6fcbfe7be08cc9')
