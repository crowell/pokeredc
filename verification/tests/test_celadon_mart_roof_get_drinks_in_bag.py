from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
from verification.harness.sm83_shims import Sm83AndRegister,Sm83LoadAAtHlIncrement,Sm83LoadAImmediate,Sm83StoreAHighImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x400000;STACK=0xD000;RETURN=0xFFFF;SITES=3;SNAP=8*len(REGISTERS)
EXPECTED=bytes.fromhex('afea37cd115bcc2108442aa7281ee5d5ea1ed1473e1ccd6d3ed1e178a728ebfa1ed11213e52137cd34e118de3eff12c9')
LIST_EXPECTED=bytes.fromhex('3c3d3e00')
W_COUNT=0xCD37;W_FILTERED=0xCC5B;W_TEMP=0xD11E
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;count:claripy.ast.BV;filtered:claripy.ast.BV;temp:claripy.ast.BV;ib0:claripy.ast.BV;ib1:claripy.ast.BV;ib2:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class PredefCall(angr.SimProcedure):
 """Proven Predef+GetQuantityOfItemInBag composition at the call site:
 record the caller-passed registers, apply this invocation's arbitrary
 matching proven transition (B := quantity, scratch rest), continue."""
 def __init__(self,next_address:int)->None:
  super().__init__();self._next=next_address
 def run(self):
  k=self.state.globals['site'];self.state.globals['site']=k+1;r=assembly_registers(self.state)
  self.state.globals[f'ib{k}']=claripy.Concat(*(r[x] for x in REGISTERS))
  for x in REGISTERS:
   v=self.state.globals[f't{k}_out_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  self.jump(self._next)
class AndACorrect(angr.SimProcedure):
 """SM83 `AND A`: Z per result, H set, N/C clear (the shared shim omits H)."""
 def __init__(self,next_address:int)->None:
  super().__init__();self._next=next_address
 def run(self):
  self.state.regs.a=self.state.regs.a & self.state.regs.a
  self.state.regs.f=claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.BVV(0x10,8)
  self.jump(self._next)
class LoadAImmNeutral(angr.SimProcedure):
 """SM83 `LD A,n` leaves F untouched; the Z80 pcode backend pollutes it."""
 def __init__(self,value:int,next_address:int)->None:
  super().__init__();self._value=value;self._next=next_address
 def run(self):
  self.state.regs.a=claripy.BVV(self._value,8);self.jump(self._next)
class NCall(angr.SimProcedure):
 def run(self):
  k=self.state.globals['site'];self.state.globals['site']=k+1;s=self.state.regs.rdi
  self.state.globals[f'ib{k}']=self.state.memory.load(s,8)
  self.state.memory.store(s,claripy.Concat(*(self.state.globals[f't{k}_out_{x}'] for x in REGISTERS)))
  ra=self.state.memory.load(self.state.regs.sp,8,endness='Iend_LE');self.state.regs.sp=self.state.regs.sp+8;self.jump(ra)
def inputs(p):
 v=symbolic_registers(p)
 for k in range(SITES):
  v[f'ib{k}']=None
  for x in REGISTERS:v[f't{k}_out_{x}']=claripy.Concat(claripy.BVS(f'{p}_t{k}_out_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(f'{p}_t{k}_out_{x}',8)
 return v
def setup(s,v):
 s.globals['site']=0
 for k in range(SITES):s.globals[f'ib{k}']=None
 for key,val in v.items():
  if key.startswith('t'):s.globals[key]=val
def assembly(v):
 l=symbol_location(SYMS,'CeladonMartRoofScript_GetDrinksInBag');lk=symbol_location(SYMS,'CeladonMartRoofDrinkList')
 assert linked_bytes(ROM,lk,len(LIST_EXPECTED))==LIST_EXPECTED and linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+1,Sm83StoreAImmediate(W_COUNT,b+4),length=3)
 p.hook(b+10,Sm83LoadAAtHlIncrement(b+11),length=1)
 p.hook(b+11,AndACorrect(b+12),length=1)
 p.hook(b+16,Sm83StoreAImmediate(W_TEMP,b+19),length=3)
 p.hook(b+20,LoadAImmNeutral(0x1C,b+22),length=2)
 p.hook(b+22,PredefCall(b+25),length=3)
 p.hook(b+28,AndACorrect(b+29),length=1)
 p.hook(b+31,Sm83LoadAImmediate(W_TEMP,b+34),length=3)
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v);s.memory.store(W_FILTERED,claripy.BVV(0,48));s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(s);m.explore(find=lambda st:st.addr==RETURN,num_find=64);assert not m.errored and m.found
 return [E(**assembly_registers(x),count=x.memory.load(W_COUNT,1),filtered=x.memory.load(W_FILTERED,6),temp=x.memory.load(W_TEMP,1),**{f'ib{k}':(x.globals[f'ib{k}'] if x.globals[f'ib{k}'] is not None else claripy.BVV(0,SNAP)) for k in range(SITES)},constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_celadon_mart_roof_script_get_drinks_in_bag');q=p.loader.find_symbol('port_get_quantity_of_item_in_bag');assert f and q
 p.hook(q.rebased_addr,NCall())
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v);s.memory.store(NM+W_FILTERED,claripy.BVV(0,48))
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and m.deadended
 return [E(**native_registers(x,NS),count=x.memory.load(NM+W_COUNT,1),filtered=x.memory.load(NM+W_FILTERED,6),temp=x.memory.load(NM+W_TEMP,1),**{f'ib{k}':(x.globals[f'ib{k}'] if x.globals[f'ib{k}'] is not None else claripy.BVV(0,SNAP)) for k in range(SITES)},constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_celadon_mart_roof_script_get_drinks_in_bag_pathwise_equivalence():
 v=inputs('get_drinks_in_bag');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'count','filtered','temp','ib0','ib1','ib2'))
