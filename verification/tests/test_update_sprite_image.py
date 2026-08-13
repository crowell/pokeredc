from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddImmediate,Sm83AddRegister,Sm83LoadAHighImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff;OFFSET=0xffda;TILE=0xff93;KEYS=('current_offset','player_tile','animation_frame','facing_direction','image_index')
class Fetch(angr.SimProcedure):
 def __init__(self,n,key,inc=False):super().__init__();self.n=n;self.key=key;self.inc=inc
 def run(self):self.state.regs.a=self.state.globals[self.key];self.state.regs.hl=self.state.regs.hl+(1 if self.inc else 0);self.jump(self.n)  # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['image_index']=self.state.regs.b;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 return i
def assembly(i):
 l=symbol_location(SYMBOLS,'UpdateSpriteImage');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q+2,Sm83LoadAHighImmediate(0xda,q+4),length=2);p.hook(q+4,Sm83AddImmediate(8,q+6),length=2);p.hook(q+7,Fetch(q+8,'animation_frame',True),length=1);p.hook(q+9,Fetch(q+10,'facing_direction'),length=1);p.hook(q+10,Sm83AddRegister('b',q+11),length=1);p.hook(q+12,Sm83LoadAHighImmediate(0x93,q+14),length=2);p.hook(q+14,Sm83AddRegister('b',q+15),length=1);p.hook(q+16,Sm83LoadAHighImmediate(0xda,q+18),length=2);p.hook(q+18,Sm83AddImmediate(2,q+20),length=2);p.hook(q+21,Store(q+22),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.memory.store(OFFSET,i['current_offset']);s.memory.store(TILE,i['player_tile'])
 for k in KEYS:s.globals[k]=i[k]
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');return [E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[k] for k in KEYS)),constraints=tuple(x.solver.constraints)) for x in collect_returns(p,s,RETURN)]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_update_sprite_image');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('update_sprite_image');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'UpdateSpriteImage');assert linked_bytes(ROM,l,23)==bytes.fromhex('26c1f0dac6086f2a477e8047f0938047f0dac6026f70c9')
