from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate, Sm83CpRegister, Sm83DecRegister

ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff
KEYS=('tile','blink_count1','blink_count2')

class Read(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)  # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.jump(self.n)  # type: ignore[override]

@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]

def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 return i
def assembly(i):
 l=symbol_location(SYMBOLS,'HandleDownArrowBlinkTiming');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address
 p.hook(q,Read('tile',q+1),length=1);p.hook(q+4,Sm83CpRegister('b',q+5),length=1)
 p.hook(q+7,Read('blink_count1',q+9),length=2);p.hook(q+9,Sm83DecRegister('a',q+10),length=1);p.hook(q+10,Store('blink_count1',q+12),length=2)
 p.hook(q+13,Read('blink_count2',q+15),length=2);p.hook(q+15,Sm83DecRegister('a',q+16),length=1);p.hook(q+16,Store('blink_count2',q+18),length=2);p.hook(q+21,Store('tile',q+22),length=1);p.hook(q+24,Store('blink_count1',q+26),length=2);p.hook(q+28,Store('blink_count2',q+30),length=2)
 p.hook(q+31,Read('blink_count1',q+33),length=2);p.hook(q+33,Sm83AndImmediate(0xff,q+34),length=1);p.hook(q+35,Sm83DecRegister('a',q+36),length=1);p.hook(q+36,Store('blink_count1',q+38),length=2);p.hook(q+39,Sm83DecRegister('a',q+40),length=1);p.hook(q+40,Store('blink_count1',q+42),length=2);p.hook(q+42,Read('blink_count2',q+44),length=2);p.hook(q+44,Sm83DecRegister('a',q+45),length=1);p.hook(q+45,Store('blink_count2',q+47),length=2);p.hook(q+50,Store('blink_count2',q+52),length=2);p.hook(q+54,Store('tile',q+55),length=1)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 return [E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[k] for k in KEYS)),constraints=tuple(x.solver.constraints)) for x in collect_returns(p,s,RETURN)]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_handle_down_arrow_blink_timing');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('down_arrow');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'HandleDownArrowBlinkTiming');assert linked_bytes(ROM,l,56)==bytes.fromhex('7e473eeeb82018f08b3de08bc0f08c3de08cc03e7f773effe08b3e06e08cc9f08ba7c83de08bc03de08bf08c3de08cc03e06e08c3eee77c9');assert symbol_location(SYMBOLS,'hDownArrowBlinkCount1').address==0xff8b;assert symbol_location(SYMBOLS,'hDownArrowBlinkCount2').address==0xff8c
