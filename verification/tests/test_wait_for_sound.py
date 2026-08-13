from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff
class ReadAlarm(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=self.state.globals['low_health_alarm'];self.jump(self.n)  # type: ignore[override]
class TerminalOr(angr.SimProcedure):
 def __init__(self,index,n):super().__init__();self.index=index;self.n=n
 def run(self):self.state.globals[f'channel{self.index}']=claripy.BVV(0,8);self.state.regs.f=claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8));self.jump(self.n)  # type: ignore[override]
class XorA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=claripy.BVV(0,8);self.state.regs.f=claripy.BVV(0x40,8);self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p);i['low_health_alarm']=claripy.BVS(p+'_alarm',8);i['channels']=claripy.BVS(p+'_channels',24);return i
def assembly(i):
 l=symbol_location(SYMBOLS,'WaitForSoundToFinish');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q,ReadAlarm(q+3),length=3);p.hook(q+3,Sm83AndImmediate(0x80,q+5),length=2);p.hook(q+10,XorA(q+11),length=1);p.hook(q+11,TerminalOr(0,q+12),length=1);p.hook(q+13,TerminalOr(1,q+14),length=1);p.hook(q+16,TerminalOr(2,q+17),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.globals['low_health_alarm']=i['low_health_alarm']
 for j in range(3):s.globals[f'channel{j}']=i['channels'][23-j*8:16-j*8]
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');return [E(**assembly_registers(x),memory=claripy.Concat(x.globals['low_health_alarm'],*(x.globals[f'channel{j}'] for j in range(3))),constraints=tuple(x.solver.constraints)) for x in collect_returns(p,s,RETURN)]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_wait_for_sound_to_finish');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(i['low_health_alarm'],i['channels']));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,4),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('wait_sound');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'WaitForSoundToFinish');assert linked_bytes(ROM,l,21)==bytes.fromhex('fa83d0e680c0e5212ac0afb623b62323b620f4e1c9')
