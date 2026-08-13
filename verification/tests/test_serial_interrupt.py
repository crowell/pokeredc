from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.rom import sm83_flags_to_z80,z80_flags_to_sm83
from verification.harness.sm83_shims import Sm83BitRegister,Sm83CpImmediate,Sm83IncRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000
YES=0xeff5;NO=0xeff6;REPEAT=0xeff7;DONE=0xeff8
NAMES=('connection_status','serial_data','receive_data','send_data','serial_control','divider','observed_divider','received_new_data')
class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
class SaveRegs(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  for r in REGISTERS:self.state.globals['saved_'+r]=(z80_flags_to_sm83(self.state.regs.f) if r=='f' else getattr(self.state.regs,r))
  self.jump(self.n)
class RestoreRegs(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  for r in REGISTERS:setattr(self.state.regs,r,(sm83_flags_to_z80(self.state.globals['saved_f']) if r=='f' else self.state.globals['saved_'+r]))
  self.jump(self.n)
class Read(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)
class Write(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.jump(self.n)
class XorA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=0;self.state.regs.f=claripy.BVV(0x40,8);self.jump(self.n)
class BranchZ(angr.SimProcedure):
 def __init__(self,z,nz):super().__init__();self.z=z;self.nz=nz
 def run(self):
  self.inhibit_autoret=True;c=(self.state.regs.f&0x40)!=0;self.successors.add_successor(self.state.copy(),self.z,c,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.nz,claripy.Not(c),'Ijk_Boring')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;saved:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 for r in REGISTERS:i['saved_'+r]=(claripy.Concat(claripy.BVS(p+'_saved_flags',4),claripy.BVV(0,4)) if r=='f' else claripy.BVS(p+'_saved_'+r,8))
 return i
def project():
 l=symbol_location(SYMBOLS,'Serial');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
def setup(s,i):
 set_assembly_registers(s,i)
 for n in NAMES:s.globals[n]=i[n]
 for r in REGISTERS:s.globals['saved_'+r]=i['saved_'+r]
def ep(x,c):return E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[n] for n in NAMES)),saved=claripy.Concat(*(x.globals['saved_'+r] for r in REGISTERS)),continuation=claripy.BVV(c,8),constraints=tuple(x.solver.constraints))
def collect(m,targets):
 m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in targets)
  if m.active:m.step()
 return m.found
def assembly_begin(i):
 p,q=project();p.hook(q,SaveRegs(q+4),length=4);p.hook(q+4,Read('connection_status',q+6),length=2);p.hook(q+6,Sm83IncRegister('a',q+7),length=1);p.hook(q+7,BranchZ(YES,NO),length=2);s=p.factory.blank_state(addr=q);setup(s,i);ends=collect(p.factory.simulation_manager(s),{YES,NO});return [ep(x,1 if x.addr==YES else 0) for x in ends]
def assembly_established(i):
 p,q=project();p.hook(q+9,Read('serial_data',q+11),length=2);p.hook(q+11,Write('receive_data',q+13),length=2);p.hook(q+13,Read('send_data',q+15),length=2);p.hook(q+15,Write('serial_data',q+17),length=2);p.hook(q+17,Read('connection_status',q+19),length=2);p.hook(q+19,Sm83CpImmediate(2,q+21),length=2);p.hook(q+21,BranchZ(DONE,q+23),length=2);p.hook(q+25,Write('serial_control',DONE),length=2);s=p.factory.blank_state(addr=q+9);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_unestablished(i):
 p,q=project();p.hook(q+29,Read('serial_data',q+31),length=2);p.hook(q+31,Write('receive_data',q+33),length=2);p.hook(q+33,Write('connection_status',q+35),length=2);p.hook(q+35,Sm83CpImmediate(2,q+37),length=2);p.hook(q+37,BranchZ(q+58,q+39),length=2);p.hook(q+39,XorA(q+40),length=1);p.hook(q+40,Write('serial_data',q+42),length=2);p.hook(q+44,Write('divider',YES),length=2);p.hook(q+58,XorA(q+59),length=1);p.hook(q+59,Write('serial_data',NO),length=2);s=p.factory.blank_state(addr=q+29);setup(s,i);ends=collect(p.factory.simulation_manager(s),{YES,NO});return [ep(x,1 if x.addr==YES else 0) for x in ends]
def assembly_divider(i):
 p,q=project();p.hook(q+46,Read('observed_divider',q+48),length=2);p.hook(q+48,Sm83BitRegister(7,'a',q+50),length=2);p.hook(q+50,BranchZ(q+52,REPEAT),length=2);p.hook(q+54,Write('serial_control',DONE),length=2);s=p.factory.blank_state(addr=q+46);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,DONE});return [ep(x,1 if x.addr==REPEAT else 0) for x in ends]
def assembly_finish(i):
 p,q=project();p.hook(q+63,Write('received_new_data',q+65),length=2);p.hook(q+67,Write('send_data',q+69),length=2);p.hook(q+69,RestoreRegs(DONE),length=5);s=p.factory.blank_state(addr=q+61);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def native(name,i,returns):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES),*(i['saved_'+r] for r in REGISTERS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),saved=x.memory.load(NATIVE_STATE+8+len(NAMES),len(REGISTERS)),continuation=(x.regs.rax[7:0] if returns else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
CASES=((assembly_begin,'port_serial_interrupt_begin',True),(assembly_established,'port_serial_interrupt_established',False),(assembly_unestablished,'port_serial_interrupt_unestablished',True),(assembly_divider,'port_serial_interrupt_divider_step',True),(assembly_finish,'port_serial_interrupt_finish',False))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('assembly,name,returns',CASES)
def test_equivalence(assembly,name,returns):
 i=inputs(name);assert_pathwise_equivalent(assembly(i),native(name,i,returns),(*REGISTERS,'memory','saved','continuation'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'Serial');assert linked_bytes(ROM,l,74)==bytes.fromhex('f5c5d5e5f0aa3c2814f001e0adf0ace001f0aafe0228263e80e0021820f001e0ade0aafe022813afe0013e03e004f004cb7f20fa3e80e0021803afe0013e01e0a93efee0ace1d1c1f1d9')
