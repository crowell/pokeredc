from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AndImmediate,Sm83CpImmediate,Sm83DecRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000
NO=0xeff5;YES=0xeff6;REPEAT=0xeff7;DONE=0xeff8
NAMES=('top_y','top_x','last_item','current_item','layout_flags','tile_behind','fetched','written','write_h','write_l','cursor_low','cursor_high','saved_h','saved_l')
class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
class Read(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)
class SaveHL(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['saved_h']=self.state.regs.h;self.state.globals['saved_l']=self.state.regs.l;self.jump(self.n)
class RestoreHL(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.h=self.state.globals['saved_h'];self.state.regs.l=self.state.globals['saved_l'];self.jump(self.n)
class StoreWrite(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['written']=self.state.regs.a;self.state.globals['write_h']=self.state.regs.h;self.state.globals['write_l']=self.state.regs.l;self.jump(self.n)
class SaveTile(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['tile_behind']=self.state.regs.a;self.jump(self.n)
class StoreGlobals(angr.SimProcedure):
 def run(self):self.state.globals['cursor_low']=self.state.regs.l;self.state.globals['cursor_high']=self.state.regs.h;self.state.globals['last_item']=self.state.globals['current_item'];self.state.regs.a=self.state.globals['current_item'];self.jump(DONE)
class BranchZ(angr.SimProcedure):
 def __init__(self,z,nz):super().__init__();self.z=z;self.nz=nz
 def run(self):
  self.inhibit_autoret=True;c=(self.state.regs.f&0x40)!=0;self.successors.add_successor(self.state.copy(),self.z,c,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.nz,claripy.Not(c),'Ijk_Boring')
class ItemSetup(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  item=self.state.regs.a;self.state.regs.b=0;self.state.regs.c=claripy.If((self.state.globals['layout_flags']&2)!=0,claripy.BVV(20,8),claripy.BVV(40,8));self.state.regs.a=item;self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'PlaceMenuCursor');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
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
def assembly_top(i):
 p,q=project();p.hook(q,Read('top_y',q+3),length=3);p.hook(q+3,Sm83AndImmediate(0xff,q+4),length=1);p.hook(q+4,BranchZ(NO,q+6),length=2);p.hook(q+12,Boundary(YES),length=1);s=p.factory.blank_state(addr=q);setup(s,i);ends=collect(p.factory.simulation_manager(s),{NO,YES});return [ep(x,1 if x.addr==YES else 0) for x in ends]
def assembly_row(i):
 p,q=project();p.hook(q+12,Sm83AddHlRegisterPair('bc',q+13),length=1);p.hook(q+13,Sm83DecRegister('a',q+14),length=1);p.hook(q+14,BranchZ(DONE,REPEAT),length=2);s=p.factory.blank_state(addr=q+12);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,DONE});return [ep(x,1 if x.addr==REPEAT else 0) for x in ends]
def assembly_x(i):
 p,q=project();p.hook(q+16,Read('top_x',q+19),length=3);p.hook(q+22,Sm83AddHlRegisterPair('bc',q+23),length=1);p.hook(q+23,SaveHL(DONE),length=1);s=p.factory.blank_state(addr=q+16);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_item(i,current):
 p,q=project();off=60 if current else 24;key='current_item' if current else 'last_item';p.hook(q+off,Read(key,q+off+3),length=3);p.hook(q+off+3,Sm83AndImmediate(0xff,q+off+4),length=1);p.hook(q+off+4,BranchZ(NO,q+off+6),length=2);p.hook(q+off+6,ItemSetup(YES),length=15);s=p.factory.blank_state(addr=q+off);setup(s,i);ends=collect(p.factory.simulation_manager(s),{NO,YES});return [ep(x,1 if x.addr==YES else 0) for x in ends]
def assembly_old_end(i):
 p,q=project();p.hook(q+50,Read('fetched',q+51),length=1);p.hook(q+51,Sm83CpImmediate(0xed,q+53),length=2);p.hook(q+53,BranchZ(q+55,q+59),length=2);p.hook(q+55,Read('tile_behind',q+58),length=3);p.hook(q+58,StoreWrite(q+59),length=1);p.hook(q+59,RestoreHL(DONE),length=1);s=p.factory.blank_state(addr=q+50);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_finish(i):
 p,q=project();p.hook(q+86,Read('fetched',q+87),length=1);p.hook(q+87,Sm83CpImmediate(0xed,q+89),length=2);p.hook(q+89,BranchZ(q+94,q+91),length=2);p.hook(q+91,SaveTile(q+94),length=3);p.hook(q+96,StoreWrite(q+97),length=1);p.hook(q+97,StoreGlobals(),length=14);s=p.factory.blank_state(addr=q+86);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def native(name,i,returns):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=(x.regs.rax[7:0] if returns else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
CASES=((assembly_top,'port_place_menu_cursor_top_begin',True),(assembly_row,'port_place_menu_cursor_row_step',True),(assembly_x,'port_place_menu_cursor_x',False),(lambda i:assembly_item(i,False),'port_place_menu_cursor_old_begin',True),(assembly_old_end,'port_place_menu_cursor_old_end',False),(lambda i:assembly_item(i,True),'port_place_menu_cursor_current_begin',True),(assembly_finish,'port_place_menu_cursor_finish',False))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('assembly,name,returns',CASES)
def test_equivalence(assembly,name,returns):
 i=inputs(name);assert_pathwise_equivalent(assembly(i),native(name,i,returns),(*REGISTERS,'memory','continuation'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'PlaceMenuCursor');assert linked_bytes(ROM,l,112)==bytes.fromhex('fa24cca7280a21a0c3011400093d20fcfa25cc06004f09e5fa2acca72814f5f0f6cb4f28050114001803012800f1093d20fc7efeed2004fa27cc77e1fa26cca72814f5f0f6cb4f28050114001803012800f1093d20fc7efeed2803ea27cc3eed777dea30cc7cea31ccfa26ccea2accc9')
