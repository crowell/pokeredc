from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;DONE=0xEFFF
FIELDS=("down_arrow_blink1","down_arrow_blink2","joy5","wait_b","wait_c","wait_d","wait_e","wait_h","wait_l")
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV; f:claripy.ast.BV; b:claripy.ast.BV; c:claripy.ast.BV; d:claripy.ast.BV; e:claripy.ast.BV; h:claripy.ast.BV; l:claripy.ast.BV
 down_arrow_blink1:claripy.ast.BV; down_arrow_blink2:claripy.ast.BV; joy5:claripy.ast.BV; wait_b:claripy.ast.BV; wait_c:claripy.ast.BV; wait_d:claripy.ast.BV; wait_e:claripy.ast.BV; wait_h:claripy.ast.BV; wait_l:claripy.ast.BV
 constraints:tuple[claripy.ast.Bool,...]
class LoadField(angr.SimProcedure):
 def __init__(self,field,next_address,length):super().__init__();self.field=field;self.next_address=next_address;self.length=length
 def run(self)->None:self.state.regs.a=self.state.globals[self.field];self.jump(self.next_address)
class PushNoOp(angr.SimProcedure):
 def run(self)->None:self.jump(self.state.addr+1)
class ZeroA(angr.SimProcedure):
 def run(self)->None:self.state.regs.a=0;self.state.regs.f=claripy.BVV(0x40,8);self.jump(self.state.addr+1)
class StoreZero(angr.SimProcedure):
 def __init__(self,field,next_address):super().__init__();self.field=field;self.next_address=next_address
 def run(self)->None:self.state.globals[self.field]=claripy.BVV(0,8);self.jump(self.next_address)
class LoadSix(angr.SimProcedure):
 def run(self)->None:self.state.regs.a=6;self.jump(self.state.addr+2)
class LoopSummary(angr.SimProcedure):
 def run(self)->None:
  self.state.solver.add((self.state.globals['joy5']&3)!=0)
  for r,f in (('b','wait_b'),('c','wait_c'),('d','wait_d'),('e','wait_e'),('h','wait_h'),('l','wait_l')):setattr(self.state.regs,r,self.state.globals[f])
  self.jump(self.state.addr+31)
class PopAF(angr.SimProcedure):
 def __init__(self,field,next_address):super().__init__();self.field=field;self.next_address=next_address
 def run(self)->None:self.state.regs.a=self.state.globals[self.field];self.state.regs.f=self.state.globals['input_f_z80'];self.jump(self.next_address)
class StoreField(angr.SimProcedure):
 def __init__(self,field,next_address):super().__init__();self.field=field;self.next_address=next_address
 def run(self)->None:self.state.globals[self.field]=self.state.regs.a;self.jump(self.next_address)
class Boundary(angr.SimProcedure):
 def run(self)->None:self.jump(DONE)
def _assembly(i):
 l=symbol_location(SYMBOLS,'WaitForTextScrollButtonPress');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q})
 p.hook(q,LoadField('down_arrow_blink1',q+2,2),length=2);p.hook(q+2,PushNoOp(),length=1);p.hook(q+3,LoadField('down_arrow_blink2',q+5,2),length=2);p.hook(q+5,PushNoOp(),length=1);p.hook(q+6,ZeroA(),length=1);p.hook(q+7,StoreZero('down_arrow_blink1',q+9),length=2);p.hook(q+9,LoadSix(),length=2);p.hook(q+11,StoreZero('down_arrow_blink2',q+13),length=2);p.hook(q+13,LoopSummary(),length=31);p.hook(q+44,PopAF('saved_down_arrow_blink2',q+45),length=1);p.hook(q+45,StoreField('down_arrow_blink2',q+47),length=2);p.hook(q+47,PopAF('saved_down_arrow_blink1',q+48),length=1);p.hook(q+48,StoreField('down_arrow_blink1',q+50),length=2);p.hook(q+50,Boundary(),length=1)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for f in FIELDS:s.globals[f]=i[f]
 s.globals['saved_down_arrow_blink1']=i['down_arrow_blink1'];s.globals['saved_down_arrow_blink2']=i['down_arrow_blink2']
 s.globals['input_f_z80']=s.regs.f;m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=1);assert len(m.found)==1;x=m.found[0]
 return [Endpoint(**assembly_registers(x),**{f:x.globals[f] for f in FIELDS},constraints=tuple(x.solver.constraints))]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_wait_for_text_scroll_button_press');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for off,f in enumerate(FIELDS,8):s.memory.store(NATIVE_STATE+off,i[f])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1;x=m.deadended[0]
 return [Endpoint(**native_registers(x,NATIVE_STATE),**{f:x.memory.load(NATIVE_STATE+off,1) for off,f in enumerate(FIELDS,8)},constraints=tuple(x.solver.constraints))]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_wait_for_text_scroll_button_press_pathwise_equivalence():
 i=symbolic_registers('wts');i['down_arrow_blink1']=claripy.BVS('wts_down1',8);i['down_arrow_blink2']=claripy.BVS('wts_down2',8);i['joy5']=claripy.BVS('wts_joy5',8);i['joy5'] = i['joy5'] | claripy.BVV(3,8)
 for f in ('wait_b','wait_c','wait_d','wait_e','wait_h','wait_l'):i[f]=claripy.BVS('wts_'+f,8)
 assert_pathwise_equivalent(_assembly(i),_native(i),('a','f','b','c','d','e','h','l',*FIELDS))
def test_wait_for_text_scroll_button_press_exact_body():
 l=symbol_location(SYMBOLS,'WaitForTextScrollButtonPress');assert linked_bytes(ROM,l,51)==bytes.fromhex('f08bf5f08cf5afe08b3e06e08ce5fa9bd0a72803cdc65621f2c4cd043ce1cd31383e2dcd6d3ef0b5e60328e1f1e08cf1e08bc9')
