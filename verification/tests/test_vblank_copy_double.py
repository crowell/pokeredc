from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83DecRegister,Sm83IncRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000
LOOP=0xeffb;REPEAT=0xeffc;DONE=0xeffd;RETURN=0xeffe
SCALARS=('sp_high','sp_low','temp_high','temp_low','source_low','source_high','dest_low','dest_high','size')
ARRAYS=tuple(f'{p}{i}' for p,n in (('source',8),('written',16),('write_h',16),('write_l',16)) for i in range(n));NAMES=SCALARS+ARRAYS
class Load(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)
class Store(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.jump(self.n)
class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
class BranchZ(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  self.inhibit_autoret=True;self.successors.add_successor(self.state.copy(),RETURN,(self.state.regs.f&0x40)!=0,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.n,(self.state.regs.f&0x40)==0,'Ijk_Boring')
class SpToHl(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.h=self.state.globals['sp_high'];self.state.regs.l=self.state.globals['sp_low'];self.jump(self.n)
class HlToSp(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['sp_high']=self.state.regs.h;self.state.globals['sp_low']=self.state.regs.l;self.jump(self.n)
class ZeroA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=0;self.state.regs.f=0x40;self.jump(self.n)
class PopDe(angr.SimProcedure):
 def __init__(self,index,n,loop=False):super().__init__();self.index=index;self.n=n;self.loop=loop
 def run(self):
  if self.loop and self.state.globals.get('entered',False):self.jump(REPEAT);return
  self.state.globals['entered']=True;self.state.regs.e=self.state.globals[f'source{self.index}'];self.state.regs.d=self.state.globals[f'source{self.index+1}'];sp=claripy.Concat(self.state.globals['sp_high'],self.state.globals['sp_low'])+2;self.state.globals['sp_high']=sp[15:8];self.state.globals['sp_low']=sp[7:0];self.jump(self.n)
class WriteReg(angr.SimProcedure):
 def __init__(self,index,reg,n):super().__init__();self.index=index;self.reg=reg;self.n=n
 def run(self):self.state.globals[f'written{self.index}']=getattr(self.state.regs,self.reg);self.state.globals[f'write_h{self.index}']=self.state.regs.h;self.state.globals[f'write_l{self.index}']=self.state.regs.l;self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'VBlankCopyDouble');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
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
 p,q=project();p.hook(q,Load('size',q+2),length=2);p.hook(q+2,Sm83AndImmediate(0xff,q+3),length=1);p.hook(q+3,BranchZ(q+4),length=1);p.hook(q+4,SpToHl(q+6),length=2);p.hook(q+7,Store('temp_high',q+9),length=2);p.hook(q+10,Store('temp_low',q+12),length=2);p.hook(q+12,Load('source_low',q+14),length=2);p.hook(q+15,Load('source_high',q+17),length=2);p.hook(q+18,HlToSp(q+19),length=1);p.hook(q+19,Load('dest_low',q+21),length=2);p.hook(q+22,Load('dest_high',q+24),length=2);p.hook(q+25,Load('size',q+27),length=2);p.hook(q+28,ZeroA(q+29),length=1);p.hook(q+29,Store('size',q+31),length=2);p.hook(q+31,Boundary(LOOP),length=1);s=p.factory.blank_state(addr=q);setup(s,i);ends=collect(p.factory.simulation_manager(s),{RETURN,LOOP});return [ep(x,0 if x.addr==RETURN else 1) for x in ends]
def assembly_step(i):
 p,q=project()
 for pair in range(4):
  base=31+pair*9;si=pair*2;oi=pair*4;p.hook(q+base,PopDe(si,q+base+1,loop=pair==0),length=1)
  for j,(off,reg) in enumerate(((1,'e'),(3,'e'),(5,'d'),(7,'d'))):p.hook(q+base+off,WriteReg(oi+j,reg,q+base+off+1),length=1)
  for off in (2,4,6):p.hook(q+base+off,Sm83IncRegister('l',q+base+off+1),length=1)
  if pair<3:p.hook(q+base+8,Sm83IncRegister('l',q+base+9),length=1)
 p.hook(q+67,Sm83DecRegister('b',q+68),length=1);p.hook(q+71,Store('dest_low',q+73),length=2);p.hook(q+74,Store('dest_high',q+76),length=2);p.hook(q+76,SpToHl(q+78),length=2);p.hook(q+79,Store('source_low',q+81),length=2);p.hook(q+82,Store('source_high',q+84),length=2);p.hook(q+84,Load('temp_high',q+86),length=2);p.hook(q+87,Load('temp_low',q+89),length=2);p.hook(q+90,HlToSp(q+91),length=1);p.hook(q+91,Boundary(DONE),length=1);s=p.factory.blank_state(addr=q+31);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,DONE});return [ep(x,1 if x.addr==REPEAT else 0) for x in ends]
def native(name,i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=x.regs.rax[7:0],constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('assembly,name',((assembly_setup,'port_vblank_copy_double_setup'),(assembly_step,'port_vblank_copy_double_step')))
def test_equivalence(assembly,name):
 i=inputs(name);assert_pathwise_equivalent(assembly(i),native(name,i),(*REGISTERS,'memory','continuation'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'VBlankCopyDouble');assert linked_bytes(ROM,l,92)==bytes.fromhex('f0cba7c8f8007ce0bf7de0c0f0cc6ff0cd67f9f0ce6ff0cf67f0cb47afe0cbd1732c732c722c722cd1732c732c722c722cd1732c732c722c722cd1732c732c722c72230520d97de0ce7ce0cff8007de0cc7ce0cdf0bf67f0c06ff9c9')
