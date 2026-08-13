from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;HALT=0xeffe;RETURN=0xefff
class StoreVBlank(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['vblank']=self.state.regs.a;self.jump(self.n)
class HaltObservation(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(HALT)
  else:self.state.globals['entered']=True;self.state.globals['vblank']=self.state.globals['observed'];self.jump(self.n)
class LoadVBlank(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=self.state.globals['vblank'];self.jump(self.n)
class AndA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.f=claripy.BVV(0x10,8)|claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8));self.jump(self.n)
class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p);i['vblank']=claripy.BVS(p+'_vblank',8);i['observed']=claripy.BVS(p+'_observed',8);return i
def project():
 l=symbol_location(SYMBOLS,'DelayFrame');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
def setup(s,i):set_assembly_registers(s,i);s.globals['vblank']=i['vblank'];s.globals['observed']=i['observed']
def ep(x,cont):return E(**assembly_registers(x),memory=claripy.Concat(x.globals['vblank'],x.globals['observed']),continuation=claripy.BVV(cont,8),constraints=tuple(x.solver.constraints))
def assembly_begin(i):
 p,q=project();p.hook(q+2,StoreVBlank(q+4),length=2);p.hook(q+4,Boundary(HALT),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=HALT);return [ep(x,1) for x in m.found]
def assembly_step(i):
 p,q=project();p.hook(q+4,HaltObservation(q+5),length=1);p.hook(q+5,LoadVBlank(q+7),length=2);p.hook(q+7,AndA(q+8),length=1);p.hook(q+10,Boundary(RETURN),length=1);s=p.factory.blank_state(addr=q+4);setup(s,i);m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {HALT,RETURN})
  if m.active:m.step()
 return [ep(x,1 if x.addr==HALT else 0) for x in m.found]
def native(name,i,step):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(i['vblank'],i['observed']));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,2),continuation=(x.regs.rax[7:0] if step else claripy.BVV(1,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('asm,name,step',((assembly_begin,'port_delay_frame_begin',False),(assembly_step,'port_delay_frame_step',True)))
def test_equivalence(asm,name,step):
 i=inputs(name);assert_pathwise_equivalent(asm(i),native(name,i,step),(*REGISTERS,'memory','continuation'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'DelayFrame');assert linked_bytes(ROM,l,11)==bytes.fromhex('3e01e0d676f0d6a720fac9')
