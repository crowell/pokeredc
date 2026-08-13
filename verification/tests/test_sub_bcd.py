from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83DecRegister,Sm83Scf
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;SUB=0xeffd;FILL=0xeffe;RETURN=0xefff
class AndA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.f=claripy.BVV(0x10,8)|claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8));self.jump(self.n)
class LoadLeft(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(SUB)
  else:self.state.globals['entered']=True;self.state.regs.a=self.state.globals['left'];self.jump(self.n)
class SbcRight(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  l=self.state.regs.a;r=self.state.globals['right'];c=self.state.regs.f&1;wide=claripy.ZeroExt(1,r)+claripy.ZeroExt(1,c);result=l-r-c;f=claripy.BVV(2,8)|claripy.If(result==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If(claripy.ZeroExt(1,l&15).ULT(claripy.ZeroExt(1,r&15)+claripy.ZeroExt(1,c)),claripy.BVV(0x10,8),claripy.BVV(0,8))|claripy.If(claripy.ZeroExt(1,l).ULT(wide),claripy.BVV(1,8),claripy.BVV(0,8));self.state.regs.a=result;self.state.regs.f=f;self.jump(self.n)
class DaaSub(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  c=self.state.regs.f&1;h=(self.state.regs.f>>4)&1;corr=claripy.If(c==1,claripy.BVV(0x60,8),claripy.BVV(0,8))|claripy.If(h==1,claripy.BVV(6,8),claripy.BVV(0,8));self.state.regs.a=self.state.regs.a-corr;self.state.regs.f=claripy.BVV(2,8)|c|claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8));self.jump(self.n)
class Store(angr.SimProcedure):
 def __init__(self,n,fill=False):super().__init__();self.n=n;self.fill=fill
 def run(self):
  if self.fill and self.state.globals.get('fill_entered',False):self.jump(FILL);return
  if self.fill:self.state.globals['fill_entered']=True
  self.state.globals['written']=self.state.regs.a;self.jump(self.n)
class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;written:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in ('left','right','written'):i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'SubBCD');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
def setup(s,i):set_assembly_registers(s,i);s.globals['left']=i['left'];s.globals['right']=i['right'];s.globals['written']=i['written']
def collect(m):
 m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {SUB,FILL,RETURN})
  if m.active:m.step()
 return m.found
def ep(x):return E(**assembly_registers(x),written=x.globals['written'],continuation=claripy.BVV({SUB:1,FILL:2,RETURN:0}[x.addr],8),constraints=tuple(x.solver.constraints))
def assembly_begin(i):
 p,q=project();p.hook(q,AndA(q+1),length=1);p.hook(q+2,Boundary(SUB),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=SUB);return [ep(x) for x in m.found]
def assembly_sub(i):
 p,q=project();p.hook(q+2,LoadLeft(q+3),length=1);p.hook(q+3,SbcRight(q+4),length=1);p.hook(q+4,DaaSub(q+5),length=1);p.hook(q+5,Store(q+6),length=1);p.hook(q+8,Sm83DecRegister('c',q+9),length=1);p.hook(q+16,Boundary(FILL),length=1);p.hook(q+22,Boundary(RETURN),length=1);s=p.factory.blank_state(addr=q+2);setup(s,i);return [ep(x) for x in collect(p.factory.simulation_manager(s))]
def assembly_fill(i):
 p,q=project();p.hook(q+16,Store(q+17,True),length=1);p.hook(q+18,Sm83DecRegister('b',q+19),length=1);p.hook(q+21,Sm83Scf(q+22),length=1);p.hook(q+22,Boundary(RETURN),length=1);s=p.factory.blank_state(addr=q+16);setup(s,i);return [ep(x) for x in collect(p.factory.simulation_manager(s))]
def native(name,i,kind):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(i['left'],i['right'],i['written']));m=p.factory.simulation_manager(s);m.run();assert not m.errored;out=[]
 for x in m.deadended:
  if kind=='begin':cont=claripy.BVV(1,8)
  elif kind=='sub':cont=x.regs.rax[7:0]
  else:cont=claripy.If(x.regs.rax[7:0]==0,claripy.BVV(2,8),claripy.BVV(0,8))
  out.append(E(**native_registers(x,NATIVE_STATE),written=x.memory.load(NATIVE_STATE+10,1),continuation=cont,constraints=tuple(x.solver.constraints)))
 return out
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('asm,name,kind',((assembly_begin,'port_sub_bcd_begin','begin'),(assembly_sub,'port_sub_bcd_step','sub'),(assembly_fill,'port_sub_bcd_fill_step','fill')))
def test_equivalence(asm,name,kind):
 i=inputs(name);assert_pathwise_equivalent(asm(i),native(name,i,kind),(*REGISTERS,'written','continuation'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'SubBCD');assert linked_bytes(ROM,l,23)==bytes.fromhex('a7411a9e27121b2b0d20f730093e001312130520fb37c9')
