from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83LoadAImmediate,Sm83StoreAHighImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xefff;AUTO=0xffba;SIZE=0xd06c
KEYS=('base_tile','auto_transfer','fetched','written','saved_b','saved_c','saved_h','saved_l','original_h','original_l','whose_turn','predef_h','predef_l','predef_d','predef_e','predef_b','predef_c','downscaled_size')
class Bound(angr.SimProcedure):
 def run(self):self.jump(DONE)  # type: ignore[override]
class RestorePredef(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  for r,k in zip('hldebc',('predef_h','predef_l','predef_d','predef_e','predef_b','predef_c')):setattr(self.state.regs,r,self.state.globals[k])
  self.state.regs.a=self.state.globals['predef_c'];self.jump(self.n)  # type: ignore[override]
class XorA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=0;self.state.regs.f=0x40;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 return i
def setup(s,i):
 set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
 s.memory.store(AUTO,i['auto_transfer']);s.memory.store(SIZE,i['downscaled_size'])
def memory(x,i):return claripy.Concat(i['base_tile'],x.memory.load(AUTO,1),*(i[k] for k in KEYS[2:17]),x.memory.load(SIZE,1))
def assembly_downscaled(i):
 l=symbol_location(SYMBOLS,'CopyDownscaledMonTiles');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;no=symbol_location(SYMBOLS,'CopyTileIDs_NoBGTransfer').address;copy=symbol_location(SYMBOLS,'CopyTileIDs').address
 p.hook(q,RestorePredef(q+3),length=3);p.hook(q+3,Sm83LoadAImmediate(SIZE,q+6),length=3);p.hook(q+6,Sm83AndImmediate(0xff,q+7),length=1);p.hook(no,XorA(no+1),length=1);p.hook(no+1,Sm83StoreAHighImmediate(0xba,copy),length=2);p.hook(copy,Bound(),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=2);return [E(**assembly_registers(x),memory=memory(x,i),constraints=tuple(x.solver.constraints)) for x in m.found]
def assembly_no_transfer(i):
 l=symbol_location(SYMBOLS,'CopyTileIDs_NoBGTransfer');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;copy=symbol_location(SYMBOLS,'CopyTileIDs').address;p.hook(q,XorA(q+1),length=1);p.hook(q+1,Sm83StoreAHighImmediate(0xba,copy),length=2);p.hook(copy,Bound(),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=DONE);return [E(**assembly_registers(m.found[0]),memory=memory(m.found[0],i),constraints=tuple(m.found[0].solver.constraints))]
def native(symbol,i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(symbol);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('asm,symbol',((assembly_no_transfer,'port_copy_tile_ids_no_bg_transfer_begin'),(assembly_downscaled,'port_copy_downscaled_mon_tiles_begin')))
def test_equivalence(asm,symbol):
 i=inputs(symbol);assert_pathwise_equivalent(asm(i),native(symbol,i),(*REGISTERS,'memory'))
def test_exact_bodies():
 l=symbol_location(SYMBOLS,'CopyTileIDs_NoBGTransfer');assert linked_bytes(ROM,l,3)==bytes.fromhex('afe0ba')
 l=symbol_location(SYMBOLS,'CopyDownscaledMonTiles');assert linked_bytes(ROM,l,17)==bytes.fromhex('cd943efa6ccda7200511025b1803111b5b')
