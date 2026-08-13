from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddImmediate,Sm83DecRegister,Sm83LoadAHighImmediate,Sm83OrRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff;OFFSET=0xffda
KEYS=('current_offset','movement_delay','facing_direction','animation_frame','intra_animation_frame','image_index','movement_status')
class Fetch(angr.SimProcedure):
 def __init__(self,n,key,delta=0):super().__init__();self.n=n;self.key=key;self.delta=delta
 def run(self):self.state.regs.a=self.state.globals[self.key];self.state.regs.hl=self.state.regs.hl+self.delta;self.jump(self.n)  # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,n,key,delta=0):super().__init__();self.n=n;self.key=key;self.delta=delta
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.state.regs.hl=self.state.regs.hl+self.delta;self.jump(self.n)  # type: ignore[override]
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
 l=symbol_location(SYMBOLS,'UpdateSpriteFacingOffsetAndDelayMovement');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address
 for o,n in ((2,4),(11,13),(21,23)):p.hook(q+o,Sm83LoadAHighImmediate(0xda,q+n),length=2)
 for o,v in ((4,8),(13,9),(23,2)):p.hook(q+o,Sm83AddImmediate(v,q+o+2),length=2)
 p.hook(q+9,Store(q+10,'movement_delay'),length=1);p.hook(q+10,Sm83DecRegister('h',q+11),length=1);p.hook(q+16,Fetch(q+17,'facing_direction',-1),length=1);p.hook(q+18,XorA(q+19),length=1);p.hook(q+19,Store(q+20,'animation_frame',-1),length=1);p.hook(q+20,Store(q+21,'intra_animation_frame'),length=1);p.hook(q+26,Fetch(q+27,'image_index'),length=1);p.hook(q+27,Sm83OrRegister('b',q+28),length=1);p.hook(q+28,Store(q+29,'image_index',-1),length=1);p.hook(q+31,Store(q+32,'movement_status'),length=1)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.memory.store(OFFSET,i['current_offset'])
 for k in KEYS:s.globals[k]=i[k]
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');ends=collect_returns(p,s,RETURN)
 return [E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[k] for k in KEYS)),constraints=tuple(x.solver.constraints)) for x in ends]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_update_sprite_facing_offset_and_delay_movement');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('sprite_facing_delay');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'UpdateSpriteFacingOffsetAndDelayMovement');assert linked_bytes(ROM,l,33)==bytes.fromhex('26c2f0dac6086f3e7f7725f0dac6096f3a47af3277f0dac6026f7eb0323e0277c9')
