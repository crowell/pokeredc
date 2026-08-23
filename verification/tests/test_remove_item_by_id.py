from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate,Sm83CpRegister,Sm83IncRegister,Sm83LoadAAtHlIncrement,Sm83LoadAHighImmediate,Sm83StoreAHighImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;STACK=0xD000;RETURN=0xFFFF;DONE=0xEFFF
EXPECTED=bytes.fromhex('211ed3f0db47afe0dc2afeffc8b8280823f0dc3ce0dc18f13e01ea96cff0dcea92cf211dd3c3bb2b')
H_ITEM_TO_REMOVE_ID=0xFFDB;H_ITEM_TO_REMOVE_INDEX=0xFFDC;W_WHICH_POKEMON=0xCF92;W_ITEM_QUANTITY=0xCF96;W_NUM_BAG_ITEMS=0xD31D;BAG_SLOTS=8;TABLE_SPAN=1+2*BAG_SLOTS;SNAP_BYTES=len(REGISTERS)+3+TABLE_SPAN
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;call:claripy.ast.BV;idx:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Boundary(angr.SimProcedure):
 """Tail-call boundary at `jp RemoveItemFromInventory`: record the complete
 callee input snapshot, then apply the shared arbitrary proven-callee
 transition (scratch registers/flags and inventory post-state)."""
 def run(self):
  r=assembly_registers(self.state);m=self.state.memory
  snap=[r[x] for x in REGISTERS]+[m.load(H_ITEM_TO_REMOVE_INDEX,1),m.load(W_WHICH_POKEMON,1),m.load(W_ITEM_QUANTITY,1)]+[m.load(W_NUM_BAG_ITEMS+i,1) for i in range(TABLE_SPAN)]
  self.state.globals['call']=claripy.Concat(*snap)
  for x in REGISTERS:
   v=self.state.globals[f'out_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  for i in range(TABLE_SPAN):m.store(W_NUM_BAG_ITEMS+i,self.state.globals[f'out_table_{i}'])
  m.store(W_WHICH_POKEMON,self.state.globals['out_cf92']);m.store(W_ITEM_QUANTITY,self.state.globals['out_cf96'])
  self.jump(DONE)
class NCall(angr.SimProcedure):
 def run(self,s,m):
  snap=[self.state.memory.load(s+i,1) for i in range(len(REGISTERS))]+[self.state.memory.load(m+H_ITEM_TO_REMOVE_INDEX,1),self.state.memory.load(m+W_WHICH_POKEMON,1),self.state.memory.load(m+W_ITEM_QUANTITY,1)]+[self.state.memory.load(m+W_NUM_BAG_ITEMS+i,1) for i in range(TABLE_SPAN)]
  self.state.globals['call']=claripy.Concat(*snap)
  self.state.memory.store(s,claripy.Concat(*(self.state.globals[f'out_{x}'] for x in REGISTERS)))
  for i in range(TABLE_SPAN):self.state.memory.store(m+W_NUM_BAG_ITEMS+i,self.state.globals[f'out_table_{i}'])
  self.state.memory.store(m+W_WHICH_POKEMON,self.state.globals['out_cf92']);self.state.memory.store(m+W_ITEM_QUANTITY,self.state.globals['out_cf96'])
def inputs(p):
 v=symbolic_registers(p)
 for x in REGISTERS:v[f'out_{x}']=claripy.Concat(claripy.BVS(p+'_out_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(f'{p}_out_{x}',8)
 for i in range(TABLE_SPAN):v[f'out_table_{i}']=claripy.BVS(f'{p}_out_table_{i}',8)
 v['out_cf92']=claripy.BVS(p+'_out_cf92',8);v['out_cf96']=claripy.BVS(p+'_out_cf96',8);v['item_id']=claripy.BVS(p+'_item_id',8);v['init_index']=claripy.BVS(p+'_init_index',8)
 for i in range(BAG_SLOTS):v[f'bag_id_{i}']=claripy.BVV(0xFF,8) if i==BAG_SLOTS-1 else claripy.BVS(f'{p}_bag_id_{i}',8);v[f'bag_qty_{i}']=claripy.BVS(f'{p}_bag_qty_{i}',8)
 return v
def setup(s,v):
 s.globals['call']=claripy.BVV(0,8*SNAP_BYTES)
 for k,f in [(k,v[k]) for k in v if k.startswith('out_')]:s.globals[k]=f
def store_memory(state,v,base=0):
 state.memory.store(base+H_ITEM_TO_REMOVE_ID,v['item_id'])
 state.memory.store(base+H_ITEM_TO_REMOVE_INDEX,v['init_index'])
 for i in range(BAG_SLOTS):state.memory.store(base+0xD31E+2*i,v[f'bag_id_{i}']);state.memory.store(base+0xD31F+2*i,v[f'bag_qty_{i}'])
 # Callee-scratched bytes the body never reads: fixed identical seeds.
 for a in (W_WHICH_POKEMON,W_ITEM_QUANTITY,W_NUM_BAG_ITEMS):state.memory.store(base+a,claripy.BVV(0,8))
def assembly(v):
 l=symbol_location(SYMS,'RemoveItemByID');t=symbol_location(SYMS,'RemoveItemFromInventory');assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+3,Sm83LoadAHighImmediate(0xDB,b+5),length=2)
 p.hook(b+7,Sm83StoreAHighImmediate(0xDC,b+9),length=2)
 p.hook(b+9,Sm83LoadAAtHlIncrement(b+10),length=1)
 p.hook(b+10,Sm83CpImmediate(0xFF,b+12),length=2)
 p.hook(b+13,Sm83CpRegister('b',b+14),length=1)
 p.hook(b+17,Sm83LoadAHighImmediate(0xDC,b+19),length=2)
 p.hook(b+19,Sm83IncRegister('a',b+20),length=1)
 p.hook(b+20,Sm83StoreAHighImmediate(0xDC,b+22),length=2)
 p.hook(b+26,Sm83StoreAImmediate(W_ITEM_QUANTITY,b+29),length=3)
 p.hook(b+29,Sm83LoadAHighImmediate(0xDC,b+31),length=2)
 p.hook(b+31,Sm83StoreAImmediate(W_WHICH_POKEMON,b+34),length=3)
 p.hook(t.address,Boundary(),length=3)
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v);store_memory(s,v);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');m=p.factory.simulation_manager(s);m.explore(find=lambda st:st.addr in (DONE,RETURN),num_find=256);assert not m.errored and m.found
 return [E(**assembly_registers(x),call=x.globals['call'],idx=x.memory.load(H_ITEM_TO_REMOVE_INDEX,1),constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_remove_item_by_id');t=p.loader.find_symbol('port_remove_item_from_inventory_wrapper');assert f and t;p.hook(t.rebased_addr,NCall());s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v);store_memory(s,v,NM);m=p.factory.simulation_manager(s);m.run();assert not m.errored and m.deadended
 return [E(**native_registers(x,NS),call=x.globals['call'],idx=x.memory.load(NM+H_ITEM_TO_REMOVE_INDEX,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_remove_item_by_id_pathwise_equivalence():
 v=inputs('remove_item_by_id');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'call','idx'))
