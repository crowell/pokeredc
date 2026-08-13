from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83LoadAHighImmediate,Sm83StoreAHighImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xefff;BASE=0xff8b;AUTO=0xffba
KEYS=('base_tile','auto_transfer','fetched','written','saved_b','saved_c','saved_h','saved_l','original_h','original_l','whose_turn')
class Bound(angr.SimProcedure):
 def run(self):self.jump(DONE)  # type: ignore[override]
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
def assembly(i):
 l=symbol_location(SYMBOLS,'CopyPicTiles');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;target=symbol_location(SYMBOLS,'CopyTileIDs_NoBGTransfer').address;copy=symbol_location(SYMBOLS,'CopyTileIDs').address
 p.hook(q,Sm83LoadAHighImmediate(0xf3,q+2),length=2);p.hook(q+2,Sm83AndImmediate(0xff,q+3),length=1);p.hook(q+7,XorA(q+8),length=1);p.hook(q+8,Sm83StoreAHighImmediate(0x8b,q+10),length=2);p.hook(target,XorA(target+1),length=1);p.hook(target+1,Sm83StoreAHighImmediate(0xba,copy),length=2);p.hook(copy,Bound(),length=1)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.memory.store(0xfff3,i['whose_turn']);s.memory.store(BASE,i['base_tile']);s.memory.store(AUTO,i['auto_transfer']);m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=2)
 return [E(**assembly_registers(x),memory=claripy.Concat(x.memory.load(BASE,1),x.memory.load(AUTO,1),*(i[k] for k in KEYS[2:])),constraints=tuple(x.solver.constraints)) for x in m.found]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_copy_pic_tiles_begin');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('copy_pic_tiles');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_entry_and_no_transfer_body():
 l=symbol_location(SYMBOLS,'CopyPicTiles');assert linked_bytes(ROM,l,12)==bytes.fromhex('f0f3a73e312801afe08b1811')
 l=symbol_location(SYMBOLS,'CopyTileIDs_NoBGTransfer');assert linked_bytes(ROM,l,3)==bytes.fromhex('afe0ba')
