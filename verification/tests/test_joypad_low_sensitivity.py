from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.rom import linked_bytes,rom_window,symbol_location
FIELDS=('joy7','joy6','pressed','held','joy5','frame_counter')
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;DONE=0xEFFF
@dataclass(frozen=True)
class Endpoint:
 joy7:claripy.ast.BV;joy6:claripy.ast.BV;pressed:claripy.ast.BV;held:claripy.ast.BV;joy5:claripy.ast.BV;frame_counter:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class JoypadEntry(angr.SimProcedure):
 def run(self)->None:self.jump(self.state.addr+3)
class LoadField(angr.SimProcedure):
 def __init__(self,field,next_address):super().__init__();self.field=field;self.next_address=next_address
 def run(self)->None:self.state.regs.a=self.state.globals[self.field];self.jump(self.next_address)
class AndA(angr.SimProcedure):
 def run(self)->None:self.state.regs.f=claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8));self.jump(self.state.addr+1)
class AndThree(angr.SimProcedure):
 def run(self)->None:self.state.regs.a=self.state.regs.a&3;self.state.regs.f=claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8));self.jump(self.state.addr+2)
class BranchZ(angr.SimProcedure):
 def __init__(self,taken,fallthrough):super().__init__();self.taken=taken;self.fallthrough=fallthrough
 def run(self)->None:
  self.inhibit_autoret=True;c=(self.state.regs.f&0x40)!=0;self.successors.add_successor(self.state.copy(),self.taken,c,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.fallthrough,claripy.Not(c),'Ijk_Boring')
class BranchNZ(angr.SimProcedure):
 def __init__(self,taken,fallthrough):super().__init__();self.taken=taken;self.fallthrough=fallthrough
 def run(self)->None:
  self.inhibit_autoret=True;c=(self.state.regs.f&0x40)==0;self.successors.add_successor(self.state.copy(),self.taken,c,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.fallthrough,claripy.Not(c),'Ijk_Boring')
class StoreJoy5(angr.SimProcedure):
 def run(self)->None:self.state.globals['joy5']=self.state.regs.a;self.jump(self.state.addr+2)
class StoreFrame(angr.SimProcedure):
 def run(self)->None:self.state.globals['frame_counter']=self.state.regs.a;self.jump(self.state.addr+2)
class LoadConstant(angr.SimProcedure):
 def __init__(self,value,next_address):super().__init__();self.value=value;self.next_address=next_address
 def run(self)->None:self.state.regs.a=self.value;self.jump(self.next_address)
class Boundary(angr.SimProcedure):
 def run(self)->None:self.jump(DONE)
def _assembly(i):
 l=symbol_location(SYMBOLS,'JoypadLowSensitivity');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q})
 p.hook(q,JoypadEntry(),length=3);p.hook(q+3,LoadField('joy7',q+5),length=2);p.hook(q+5,AndA(),length=1);p.hook(q+6,LoadField('pressed',q+8),length=2);p.hook(q+8,BranchZ(q+12,q+10),length=2);p.hook(q+10,LoadField('held',q+12),length=2);p.hook(q+12,StoreJoy5(),length=2);p.hook(q+14,LoadField('pressed',q+16),length=2);p.hook(q+16,AndA(),length=1);p.hook(q+17,BranchZ(q+24,q+19),length=2);p.hook(q+19,LoadConstant(30,q+21),length=2);p.hook(q+21,StoreFrame(),length=2);p.hook(q+23,Boundary(),length=1);p.hook(q+24,LoadField('frame_counter',q+26),length=2);p.hook(q+26,AndA(),length=1);p.hook(q+27,BranchZ(q+33,q+29),length=2);p.hook(q+29,LoadConstant(0,q+30),length=1);p.hook(q+30,StoreJoy5(),length=2);p.hook(q+32,Boundary(),length=1);p.hook(q+33,LoadField('held',q+35),length=2);p.hook(q+35,AndThree(),length=2);p.hook(q+37,BranchZ(q+47,q+39),length=2);p.hook(q+39,LoadField('joy6',q+41),length=2);p.hook(q+41,AndA(),length=1);p.hook(q+42,BranchNZ(q+47,q+44),length=2);p.hook(q+44,LoadConstant(0,q+45),length=1);p.hook(q+45,StoreJoy5(),length=2);p.hook(q+47,LoadConstant(5,q+49),length=2);p.hook(q+49,StoreFrame(),length=2);p.hook(q+51,Boundary(),length=1)
 s=p.factory.blank_state(addr=q); 
 for f in FIELDS:s.globals[f]=i[f]
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=16);assert m.found
 return [Endpoint(**{f:x.globals[f] for f in FIELDS},constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_joypad_low_sensitivity');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE)
 for off,f in enumerate(FIELDS):s.memory.store(NATIVE_STATE+off,i[f])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and m.deadended
 return [Endpoint(**{f:x.memory.load(NATIVE_STATE+off,1) for off,f in enumerate(FIELDS)},constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_joypad_low_sensitivity_pathwise_equivalence():
 i={f:claripy.BVS('jls_'+f,8) for f in FIELDS};assert_pathwise_equivalent(_assembly(i),_native(i),FIELDS)
def test_joypad_low_sensitivity_exact_body():
 l=symbol_location(SYMBOLS,'JoypadLowSensitivity');assert linked_bytes(ROM,l,52)==bytes.fromhex('cd9a01f0b7a7f0b32802f0b4e0b5f0b3a728053e1ee0d5c9f0d5a72804afe0b5c9f0b4e6032808f0b6a72003afe0b53e05e0d5c9')
