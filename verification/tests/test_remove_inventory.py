from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
from verification.harness.sm83_shims import Sm83AddRegister,Sm83CpImmediate,Sm83DecRegister,Sm83IncRegister,Sm83SlaRegister,Sm83SubRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;LOOP=0xeffd;POST=0xeffe;RETURN=0xefff
NAMES=('which_item','item_quantity','max_item_quantity','current_quantity','fetched_next','written','list_scroll_offset','current_menu_item','bag_saved_menu_item','saved_list_scroll_offset','inventory_count','list_count','max_menu_item','saved_h','saved_l')
class SaveHL(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['saved_h']=self.state.regs.h;self.state.globals['saved_l']=self.state.regs.l;self.jump(self.n)
class RestoreHL(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.h=self.state.globals['saved_h'];self.state.regs.l=self.state.globals['saved_l'];self.jump(self.n)
class Load(angr.SimProcedure):
 def __init__(self,key,n,hld=False):super().__init__();self.key=key;self.n=n;self.hld=hld
 def run(self):self.state.regs.a=self.state.globals[self.key];self.state.regs.hl=self.state.regs.hl-(1 if self.hld else 0);self.jump(self.n)
class Store(angr.SimProcedure):
 def __init__(self,key,n,delta=0):super().__init__();self.key=key;self.n=n;self.delta=delta
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.state.regs.hl=self.state.regs.hl+self.delta;self.jump(self.n)
class AndA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.f=claripy.BVV(0x10,8)|claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8));self.jump(self.n)
class ZeroA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=claripy.BVV(0,8);self.state.regs.f=claripy.BVV(0x40,8);self.jump(self.n)
class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
class LoopLoad(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(LOOP)
  else:self.state.globals['entered']=True;self.state.regs.a=self.state.globals['fetched_next'];self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'RemoveItemFromInventory_');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
def setup(s,i):
 set_assembly_registers(s,i)
 for n in NAMES:s.globals[n]=i[n]
def ep(x,cont):return E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[n] for n in NAMES)),continuation=claripy.BVV(cont,8),constraints=tuple(x.solver.constraints))
def collect(m,targets):
 m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in targets)
  if m.active:m.step()
 return m.found
def assembly_begin(i):
 p,q=project();p.hook(q,SaveHL(q+1),length=1);p.hook(q+2,Load('which_item',q+5),length=3);p.hook(q+5,Sm83SlaRegister('a',q+7),length=2);p.hook(q+7,Sm83AddRegister('l',q+8),length=1);p.hook(q+11,Sm83IncRegister('h',q+12),length=1);p.hook(q+13,Load('item_quantity',q+16),length=3);p.hook(q+17,Load('current_quantity',q+18),length=1);p.hook(q+18,Sm83SubRegister('e',q+19),length=1);p.hook(q+19,Store('written',q+20,delta=-1),length=1);p.hook(q+20,Store('max_item_quantity',q+23),length=3);p.hook(q+23,AndA(q+24),length=1);p.hook(q+30,Boundary(LOOP),length=1);p.hook(q+66,RestoreHL(q+67),length=1);p.hook(q+67,Boundary(RETURN),length=1);s=p.factory.blank_state(addr=q);setup(s,i);return [ep(x,1 if x.addr==LOOP else 0) for x in collect(p.factory.simulation_manager(s),{LOOP,RETURN})]
def assembly_step(i):
 p,q=project();p.hook(q+30,LoopLoad(q+31),length=1);p.hook(q+32,Store('written',q+33,delta=1),length=1);p.hook(q+33,Sm83CpImmediate(0xff,q+35),length=2);p.hook(q+37,Boundary(POST),length=1);s=p.factory.blank_state(addr=q+30);setup(s,i);return [ep(x,1 if x.addr==LOOP else 0) for x in collect(p.factory.simulation_manager(s),{LOOP,POST})]
def assembly_finish(i):
 p,q=project();p.hook(q+37,ZeroA(q+38),length=1)
 for off,key,nxt in ((38,'list_scroll_offset',41),(41,'current_menu_item',44),(44,'bag_saved_menu_item',47),(47,'saved_list_scroll_offset',50),(53,'inventory_count',54),(54,'list_count',57),(61,'max_menu_item',64)):p.hook(q+off,Store(key,q+nxt),length=nxt-off)
 p.hook(q+50,RestoreHL(q+51),length=1);p.hook(q+51,Load('inventory_count',q+52),length=1);p.hook(q+52,Sm83DecRegister('a',q+53),length=1);p.hook(q+57,Sm83CpImmediate(2,q+59),length=2);p.hook(q+67,Boundary(RETURN),length=1);s=p.factory.blank_state(addr=q+37);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=RETURN,num_find=2);return [ep(x,0) for x in m.found]
def native(name,i,kind):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;out=[]
 for x in m.deadended:
  cont=x.regs.rax[7:0] if kind in {'begin','step'} else claripy.BVV(0,8);out.append(E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=cont,constraints=tuple(x.solver.constraints)))
 return out
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('asm,name,kind',((assembly_begin,'port_remove_item_from_inventory_begin','begin'),(assembly_step,'port_remove_item_from_inventory_step','step'),(assembly_finish,'port_remove_item_from_inventory_finish','finish')))
def test_equivalence(asm,name,kind):
 i=inputs(name);assert_pathwise_equivalent(asm(i),native(name,i,kind),(*REGISTERS,'memory','continuation'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'RemoveItemFromInventory_');assert linked_bytes(ROM,l,68)==bytes.fromhex('e523fa92cfcb27856f30012423fa96cf5f7e9332ea97cfa720285d5413131a1322feff20f9afea36ccea26ccea2cccea7ed0e17e3d77ea2ad1fe023806ea28cc1801e1c9')
