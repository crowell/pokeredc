from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddImmediate,Sm83AddRegister,Sm83AndImmediate,Sm83DecRegister,Sm83IncRegister,Sm83OrRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000
COLUMN=0xeff8;ROW=0xeff9;REPEAT=0xeffa;DONE=0xeffb;RETURN=0xeffc
NAMES=('mode','dest_low','dest_high','fetched0','fetched1','written0','written1','write_h0','write_l0','write_h1','write_l1','saved_d','saved_e')
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
class ZeroA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=0;self.state.regs.f=0x40;self.jump(self.n)
class LoopLoad(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(REPEAT)
  else:self.state.globals['entered']=True;self.state.regs.a=self.state.globals['fetched0'];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
class Write(angr.SimProcedure):
 def __init__(self,index,n):super().__init__();self.index=index;self.n=n
 def run(self):self.state.globals[f'written{self.index}']=self.state.regs.a;self.state.globals[f'write_h{self.index}']=self.state.regs.d;self.state.globals[f'write_l{self.index}']=self.state.regs.e;self.jump(self.n)
class LoadSecond(Load):
 def run(self):self.state.regs.a=self.state.globals['fetched1'];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
class SaveDe(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['saved_d']=self.state.regs.d;self.state.globals['saved_e']=self.state.regs.e;self.jump(self.n)
class RestoreDe(SaveDe):
 def run(self):self.state.regs.d=self.state.globals['saved_d'];self.state.regs.e=self.state.globals['saved_e'];self.jump(self.n)
class OrImmediate(angr.SimProcedure):
 def __init__(self,value,n):super().__init__();self.value=value;self.n=n
 def run(self):self.state.regs.a|=self.value;self.state.regs.f=claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8));self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'RedrawRowOrColumn');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
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
 p,q=project();p.hook(q,Load('mode',q+2),length=2);p.hook(q+2,Sm83AndImmediate(0xff,q+3),length=1);p.hook(q+3,BranchZ(q+4),length=1);p.hook(q+5,ZeroA(q+6),length=1);p.hook(q+6,Store('mode',q+8),length=2);p.hook(q+8,Sm83DecRegister('b',q+9),length=1);p.hook(q+14,Load('dest_low',q+16),length=2);p.hook(q+17,Load('dest_high',q+19),length=2);p.hook(q+22,Boundary(COLUMN),length=1);p.hook(q+50,Load('dest_low',q+52),length=2);p.hook(q+53,Load('dest_high',q+55),length=2);p.hook(q+56,SaveDe(q+65),length=4);p.hook(q+67,Boundary(ROW),length=1);s=p.factory.blank_state(addr=q);setup(s,i);ends=collect(p.factory.simulation_manager(s),{RETURN,COLUMN,ROW});codes={RETURN:0,COLUMN:1,ROW:2};return [ep(x,codes[x.addr]) for x in ends]
def assembly_column(i):
 p,q=project();p.hook(q+22,LoopLoad(q+23),length=1);p.hook(q+23,Write(0,q+24),length=1);p.hook(q+25,LoadSecond('fetched1',q+26),length=1);p.hook(q+26,Write(1,q+27),length=1);p.hook(q+29,Sm83AddRegister('e',q+30),length=1);p.hook(q+33,Sm83IncRegister('d',q+34),length=1);p.hook(q+35,Sm83AndImmediate(3,q+37),length=2);p.hook(q+37,OrImmediate(0x98,q+39),length=2);p.hook(q+40,Sm83DecRegister('c',q+41),length=1);p.hook(q+43,ZeroA(q+44),length=1);p.hook(q+44,Store('mode',q+46),length=2);p.hook(q+46,Boundary(DONE),length=1);s=p.factory.blank_state(addr=q+22);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,DONE});return [ep(x,1 if x.addr==REPEAT else 0) for x in ends]
def assembly_row_half(i):
 p,q=project();p.hook(q+67,LoopLoad(q+68),length=1);p.hook(q+68,Write(0,q+69),length=1);p.hook(q+70,LoadSecond('fetched1',q+71),length=1);p.hook(q+71,Write(1,q+72),length=1);p.hook(q+73,Sm83IncRegister('a',q+74),length=1);p.hook(q+74,Sm83AndImmediate(31,q+76),length=2);p.hook(q+78,Sm83AndImmediate(0xe0,q+80),length=2);p.hook(q+80,Sm83OrRegister('b',q+81),length=1);p.hook(q+82,Sm83DecRegister('c',q+83),length=1);p.hook(q+85,Boundary(DONE),length=1);s=p.factory.blank_state(addr=q+67);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,DONE});return [ep(x,1 if x.addr==REPEAT else 0) for x in ends]
def assembly_between(i):
 p,q=project();p.hook(q+60,RestoreDe(q+61),length=1);p.hook(q+63,Sm83AddRegister('e',q+64),length=1);p.hook(q+67,Boundary(DONE),length=1);s=p.factory.blank_state(addr=q+60);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=DONE);return [ep(x,0) for x in m.found]
def native(name,i,returns):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=(x.regs.rax[7:0] if returns else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
CASES=((assembly_setup,'port_redraw_row_or_column_setup',True),(assembly_column,'port_redraw_column_step',True),(assembly_row_half,'port_redraw_row_half_step',True),(assembly_between,'port_redraw_row_between_halves',False))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('assembly,name,returns',CASES)
def test_equivalence(assembly,name,returns):
 i=inputs(name);assert_pathwise_equivalent(assembly(i),native(name,i,returns),(*REGISTERS,'memory','continuation'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'RedrawRowOrColumn');assert linked_bytes(ROM,l,86)==bytes.fromhex('f0d0a7c847afe0d005202421fccbf0d15ff0d2570e122a12132a123e1f835f3001147ae603f698570d20ebafe0d0c921fccbf0d15ff0d257d5cd421dd13e20835f0e0a2a12132a127b3ce61f477be6e0b05f0d20eec9')
