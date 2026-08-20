from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
FIELDS=('money0','money1','money2','price0','price1','price2','textbox','sound_a','sound_f','sound_b','sound_c','sound_d','sound_e','sound_h','sound_l')
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;DONE=0xEFFF
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
 money0:claripy.ast.BV;money1:claripy.ast.BV;money2:claripy.ast.BV;price0:claripy.ast.BV;price1:claripy.ast.BV;price2:claripy.ast.BV;textbox:claripy.ast.BV;sound_a:claripy.ast.BV;sound_f:claripy.ast.BV;sound_b:claripy.ast.BV;sound_c:claripy.ast.BV;sound_d:claripy.ast.BV;sound_e:claripy.ast.BV;sound_h:claripy.ast.BV;sound_l:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class LoadPair(angr.SimProcedure):
 def __init__(self,pair,value,next_address,length):super().__init__();self.pair=pair;self.value=value;self.next_address=next_address;self.length=length
 def run(self)->None:
  hi,lo=self.pair;setattr(self.state.regs,hi,claripy.BVV(self.value>>8,8));setattr(self.state.regs,lo,claripy.BVV(self.value&0xff,8));self.jump(self.next_address)
class LoadC(angr.SimProcedure):
 def run(self)->None:self.state.regs.c=3;self.jump(self.state.addr+2)
class LoadA(angr.SimProcedure):
 def __init__(self,value,next_address):super().__init__();self.value=value;self.next_address=next_address
 def run(self)->None:self.state.regs.a=self.value;self.jump(self.state.addr+2)
class AddBcdSummary(angr.SimProcedure):
 def run(self)->None:
  # The packed-BCD operation is represented by the explicit state memory fields;
  # use the same deterministic nibble algorithm as the native contract.
  carry=claripy.BVV(0,8)
  for n in (2,1,0):
   dest=self.state.globals[f'money{n}'];src=self.state.globals[f'price{n}']
   low_raw=(dest&0xf)+(src&0xf)+carry
   low_carry=low_raw>=10
   low=claripy.If(low_carry,low_raw-10,low_raw)
   high_raw=((dest>>4)&0xf)+((src>>4)&0xf)
   high_with=high_raw+claripy.If(low_carry,claripy.BVV(1,8),claripy.BVV(0,8))
   high_carry=high_with>=10
   high=claripy.If(high_carry,high_with-10,high_with)
   carry=claripy.If(high_carry,claripy.BVV(1,8),claripy.BVV(0,8))
   self.state.globals[f'money{n}']=(high<<4)|low
  for n in (0,1,2):
   self.state.globals[f'money{n}']=claripy.If(carry != 0,claripy.BVV(0x99,8),self.state.globals[f'money{n}'])
  self.jump(self.state.addr+3)
class StoreTextbox(angr.SimProcedure):
 def run(self)->None:self.state.globals['textbox']=self.state.regs.a;self.jump(self.state.addr+3)
class NoOp(angr.SimProcedure):
 def run(self)->None:self.jump(self.state.addr+3)
class SoundSummary(angr.SimProcedure):
 def run(self)->None:
  self.state.regs.a=self.state.globals['sound_a'];self.state.regs.f=sm83_flags_to_z80(self.state.globals['sound_f'])
  for r in ('b','c','d','e','h','l'):setattr(self.state.regs,r,self.state.globals['sound_'+r])
  self.jump(self.state.addr+3)
class Boundary(angr.SimProcedure):
 def run(self)->None:self.jump(DONE)
def _assembly(i):
 l=symbol_location(SYMBOLS,'AddAmountSoldToMoney');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q})
 p.hook(q,LoadPair('de',0xd349,q+3,3),length=3);p.hook(q+3,LoadPair('hl',0xffa1,q+6,3),length=3);p.hook(q+6,LoadC(),length=2);p.hook(q+8,LoadA(0x0b,q+10),length=2);p.hook(q+10,AddBcdSummary(),length=3);p.hook(q+13,LoadA(0x13,q+15),length=2);p.hook(q+15,StoreTextbox(),length=3);p.hook(q+18,NoOp(),length=3);p.hook(q+21,LoadA(0xb2,q+23),length=2);p.hook(q+23,SoundSummary(),length=3);p.hook(q+26,Boundary(),length=3)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for f in FIELDS:s.globals[f]=i[f]
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=1);assert len(m.found)==1;x=m.found[0];return [Endpoint(**assembly_registers(x),**{f:x.globals[f] for f in FIELDS},constraints=tuple(x.solver.constraints))]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_add_amount_sold_to_money');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for off,f in enumerate(FIELDS,8):s.memory.store(NATIVE_STATE+off,i[f])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==2;return [Endpoint(**native_registers(x,NATIVE_STATE),**{f:x.memory.load(NATIVE_STATE+off,1) for off,f in enumerate(FIELDS,8)},constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_add_amount_sold_to_money_pathwise_equivalence():
 i=symbolic_registers('aasm')
 for f in FIELDS:i[f]=claripy.BVS('aasm_'+f,8)
 i['sound_f']=claripy.Concat(claripy.BVS('aasm_sound_flags',4),claripy.BVV(0,4))
 assert_pathwise_equivalent(_assembly(i),_native(i),('a','f','b','c','d','e','h','l',*FIELDS))
def test_add_amount_sold_to_money_exact_body():
 l=symbol_location(SYMBOLS,'AddAmountSoldToMoney');assert linked_bytes(ROM,l,29)==bytes.fromhex('1149d321a1ff0e033e0bcd6d3e3e13ea25d1cde8303eb2cd4037c34837')
