from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
from verification.harness.sm83_shims import Sm83AndRegister,Sm83LoadAAtHlIncrement,Sm83StoreAHighImmediate
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;STACK=0xD000;RETURN=0xFFFF;DONE=0xEFFF;SITES=3;SNAP=8*len(REGISTERS)
EXPECTED=bytes.fromhex('21b7652ae0dba7c8e547cd9334e128f3060521377fc3d6353c3d3e')
LIST_EXPECTED=bytes.fromhex('3c3d3e00')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;ffdb:claripy.ast.BV;ib0:claripy.ast.BV;ib1:claripy.ast.BV;ib2:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class ACall(angr.SimProcedure):
 """Proven IsItemInBag composition boundary at the call site: record the
 caller-passed state, apply this call site's arbitrary matching proven
 transition, then continue after the replaced CALL."""
 def __init__(self,next_address:int)->None:
  super().__init__();self._next=next_address
 def run(self):
  k=self.state.globals['site'];self.state.globals['site']=k+1;r=assembly_registers(self.state)
  self.state.globals[f'ib{k}']=claripy.Concat(*(r[x] for x in REGISTERS))
  for x in REGISTERS:
   v=self.state.globals[f't{k}_out_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  self.jump(self._next)
class FarJp(angr.SimProcedure):
 """`jp Bankswitch` tail: the unproven dispatcher is the path boundary; the
 far-call argument state (B/H/L plus preserved registers) is compared."""
 def run(self):self.jump(DONE)
class NCall(angr.SimProcedure):
 def run(self,s,m):
  k=self.state.globals['site'];self.state.globals['site']=k+1
  self.state.globals[f'ib{k}']=claripy.Concat(*(self.state.memory.load(s+i,1) for i in range(len(REGISTERS))))
  self.state.memory.store(s,claripy.Concat(*(self.state.globals[f't{k}_out_{x}'] for x in REGISTERS)))
def inputs(p):
 v=symbolic_registers(p)
 for k in range(SITES):
  for x in REGISTERS:v[f't{k}_out_{x}']=claripy.Concat(claripy.BVS(f'{p}_t{k}_out_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(f'{p}_t{k}_out_{x}',8)
 return v
def setup(s,v):
 s.globals['site']=0
 for k in range(SITES):s.globals[f'ib{k}']=None
 for key,val in v.items():
  if key.startswith('t'):s.globals[key]=val
def assembly(v):
 l=symbol_location(SYMS,'RemoveGuardDrink');i=symbol_location(SYMS,'IsItemInBag');lk=symbol_location(SYMS,'GuardDrinksList')
 assert linked_bytes(ROM,lk,len(LIST_EXPECTED))==LIST_EXPECTED and linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+3,Sm83LoadAAtHlIncrement(b+4),length=1)
 p.hook(b+4,Sm83StoreAHighImmediate(0xDB,b+6),length=2)
 p.hook(b+10,ACall(b+13),length=3)
 p.hook(symbol_location(SYMS,'Bankswitch').address,FarJp(),length=3)
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');m=p.factory.simulation_manager(s);m.explore(find=lambda st:st.addr in (DONE,RETURN),num_find=64);assert not m.errored and len(m.found)==SITES+1
 return [E(**assembly_registers(x),ffdb=x.memory.load(0xFFDB,1),**{f'ib{k}':(x.globals[f'ib{k}'] if x.globals[f'ib{k}'] is not None else claripy.BVV(0,SNAP)) for k in range(SITES)},constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_remove_guard_drink');t=p.loader.find_symbol('port_is_item_in_bag');assert f and t;p.hook(t.rebased_addr,NCall());s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v);m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==SITES+1
 return [E(**native_registers(x,NS),ffdb=x.memory.load(NM+0xFFDB,1),**{f'ib{k}':(x.globals[f'ib{k}'] if x.globals[f'ib{k}'] is not None else claripy.BVV(0,SNAP)) for k in range(SITES)},constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_remove_guard_drink_pathwise_equivalence():
 v=inputs('remove_guard_drink');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'ffdb','ib0','ib1','ib2'))
