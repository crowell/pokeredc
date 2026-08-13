from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location,z80_flags_to_sm83
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AddRegister,Sm83CpImmediate,Sm83CpRegister,Sm83DecRegister,Sm83Scf,Sm83SubImmediate,Sm83SubRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;RET=0xeffb;SCAN=0xeffc;NEW=0xeffd;QTY=0xeffe
NAMES=('cur_item','item_quantity','inventory_count','fetched_item','fetched_marker','existing_quantity','count_written','item_written','quantity_written','terminator_written','quantity_write_valid','add_write_valid','saved_a','saved_f','saved_b','saved_c','saved_d','saved_e','saved_h','saved_l')
class Load(angr.SimProcedure):
 def __init__(self,key,n,hli=False,meta=None):super().__init__();self.key=key;self.n=n;self.hli=hli;self.meta=meta
 def run(self):
  self.state.regs.a=self.state.globals[self.key]
  if self.hli:self.state.regs.hl=self.state.regs.hl+1
  if self.meta:self.state.globals[self.meta]=claripy.BVV(0,8)
  self.jump(self.n)
class Store(angr.SimProcedure):
 def __init__(self,key,n,hli=False,valid=None):super().__init__();self.key=key;self.n=n;self.hli=hli;self.valid=valid
 def run(self):
  self.state.globals[self.key]=self.state.regs.a
  if self.hli:self.state.regs.hl=self.state.regs.hl+1
  if self.valid:self.state.globals[self.valid]=claripy.BVV(1,8)
  self.jump(self.n)
class AndA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.f=claripy.BVV(0x10,8)|claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8));self.jump(self.n)
class Save(angr.SimProcedure):
 def __init__(self,kind,n):super().__init__();self.kind=kind;self.n=n
 def run(self):
  for r in self.kind:self.state.globals['saved_'+r]=z80_flags_to_sm83(self.state.regs.f) if r=='f' else getattr(self.state.regs,r)
  self.jump(self.n)
class RestoreHL(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.h=self.state.globals['saved_h'];self.state.regs.l=self.state.globals['saved_l'];self.jump(self.n)
class Unwind(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  for r in ('h','l','d','e'):setattr(self.state.regs,r,self.state.globals['saved_'+r])
  self.state.regs.b=self.state.globals['saved_a'];self.state.regs.c=self.state.globals['saved_f'];self.jump(self.n)
class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
class LoopItem(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(SCAN)
  else:self.state.globals['entered']=True;self.state.regs.a=self.state.globals['fetched_item'];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
class IncCount(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  old=self.state.globals['inventory_count'];new=old+1;self.state.globals['inventory_count']=new;self.state.globals['count_written']=new;f=self.state.regs.f&1;f|=claripy.If(new==0,claripy.BVV(0x40,8),claripy.BVV(0,8));f|=claripy.If((old&15)==15,claripy.BVV(0x10,8),claripy.BVV(0,8));self.state.regs.f=f;self.jump(self.n)
class StoreTerm(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['terminator_written']=claripy.BVV(0xff,8);self.state.globals['add_write_valid']=claripy.BVV(1,8);self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'AddItemToInventory_');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
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
def common_terminal(p,q):
 p.hook(q+103,Unwind(q+107),length=4);p.hook(q+108,Store('item_quantity',q+111),length=3);p.hook(q+111,Boundary(RET),length=1)
def assembly_setup(i):
 p,q=project();p.hook(q,Load('item_quantity',q+3),length=3);p.hook(q+3,Save('af',q+4),length=1);p.hook(q+4,Save('bc',q+5),length=1);p.hook(q+5,Save('de',q+6),length=1);p.hook(q+6,Save('hl',q+7),length=1);p.hook(q+7,Boundary(q+8),length=1);p.hook(q+12,Sm83CpRegister('l',q+13),length=1);p.hook(q+17,Sm83CpRegister('h',q+18),length=1);p.hook(q+22,Load('inventory_count',q+23),length=1);p.hook(q+23,Sm83SubRegister('d',q+24),length=1);p.hook(q+25,Load('inventory_count',q+26,hli=True),length=1);p.hook(q+26,AndA(q+27),length=1);p.hook(q+29,Boundary(SCAN),length=1);p.hook(q+44,RestoreHL(NEW),length=1);s=p.factory.blank_state(addr=q);setup(s,i);return [ep(x,1 if x.addr==SCAN else 2) for x in collect(p.factory.simulation_manager(s),{SCAN,NEW})]
def assembly_scan(i):
 p,q=project();p.hook(q+29,LoopItem(q+30),length=1);p.hook(q+31,Load('cur_item',q+34),length=3);p.hook(q+34,Sm83CpRegister('b',q+35),length=1);p.hook(q+39,Load('fetched_marker',q+40),length=1);p.hook(q+40,Sm83CpImmediate(0xff,q+42),length=2);p.hook(q+44,RestoreHL(NEW),length=1);p.hook(q+70,Boundary(QTY),length=3);s=p.factory.blank_state(addr=q+29);setup(s,i);ends=collect(p.factory.simulation_manager(s),{SCAN,NEW,QTY});return [ep(x,{SCAN:1,NEW:2,QTY:3}[x.addr]) for x in ends]
def assembly_quantity(i):
 p,q=project();p.hook(q+70,Load('item_quantity',q+73,meta='quantity_write_valid'),length=3);p.hook(q+74,Load('existing_quantity',q+75),length=1);p.hook(q+75,Sm83AddRegister('b',q+76),length=1);p.hook(q+76,Sm83CpImmediate(100,q+78),length=2);p.hook(q+81,Sm83SubImmediate(99,q+83),length=2);p.hook(q+83,Store('item_quantity',q+86),length=3);p.hook(q+87,AndA(q+88),length=1);p.hook(q+92,Store('quantity_written',q+93,hli=True,valid='quantity_write_valid'),length=1);p.hook(q+29,Boundary(SCAN),length=1);p.hook(q+96,RestoreHL(q+97),length=1);p.hook(q+97,AndA(q+98),length=1);p.hook(q+100,Store('quantity_written',q+101,valid='quantity_write_valid'),length=1);p.hook(q+101,RestoreHL(q+102),length=1);p.hook(q+102,Sm83Scf(q+103),length=1);common_terminal(p,q);s=p.factory.blank_state(addr=q+70);setup(s,i);ends=collect(p.factory.simulation_manager(s),{SCAN,RET});return [ep(x,1 if x.addr==SCAN else 0) for x in ends]
def assembly_new(i):
 p,q=project();p.hook(q+45,Boundary(q+45),length=0) if False else None;p.hook(q+46,AndA(q+47),length=1);p.hook(q+49,IncCount(q+50),length=1);p.hook(q+50,Load('inventory_count',q+51),length=1);p.hook(q+51,Sm83AddRegister('a',q+52),length=1);p.hook(q+52,Sm83DecRegister('a',q+53),length=1);p.hook(q+56,Sm83AddHlRegisterPair('bc',q+57),length=1);p.hook(q+57,Load('cur_item',q+60),length=3);p.hook(q+60,Store('item_written',q+61,hli=True),length=1);p.hook(q+61,Load('item_quantity',q+64),length=3);p.hook(q+64,Store('quantity_written',q+65,hli=True),length=1);p.hook(q+65,StoreTerm(q+67),length=2);p.hook(q+102,Sm83Scf(q+103),length=1);common_terminal(p,q);s=p.factory.blank_state(addr=q+45);setup(s,i);s.globals['add_write_valid']=claripy.BVV(0,8);m=p.factory.simulation_manager(s);m.explore(find=RET,num_find=2);return [ep(x,0) for x in m.found]
def native(name,i,returns):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=(x.regs.rax[7:0] if returns else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('asm,name,returns',((assembly_setup,'port_add_item_to_inventory_setup',True),(assembly_scan,'port_add_item_to_inventory_scan',True),(assembly_quantity,'port_add_item_to_inventory_quantity',True),(assembly_new,'port_add_item_to_inventory_new',False)))
def test_equivalence(asm,name,returns):
 i=inputs(name);assert_pathwise_equivalent(asm(i),native(name,i,returns),(*REGISTERS,'memory','continuation'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'AddItemToInventory_');assert linked_bytes(ROM,l,112)==bytes.fromhex('fa96cff5c5d5e5e516323e1dbd20073ed3bc200216147e92572aa7280f2a47fa91cfb8ca4a4e237efeff20f1e17aa72836347e873d4f060009fa91cf22fa96cf2236ffc36a4efa96cf477e80fe64da684ed663ea96cf7aa728063e6322c3214ee1a7180377e137e1d1c1c178ea96cfc9')
