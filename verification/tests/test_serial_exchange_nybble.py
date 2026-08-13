from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddImmediate,Sm83AndImmediate,Sm83CpImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff
KEYS=('send_data','temp_receive_data','receive_data','connection_status','serial_send_data','serial_receive_data','serial_control')
class XorA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=claripy.BVV(0,8);self.state.regs.f=claripy.BVV(0x40,8);self.jump(self.n)  # type: ignore[override]
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
 l=symbol_location(SYMBOLS,'Serial_ExchangeNybble');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q+3,Read('send_data',q+6),length=3);p.hook(q+6,Sm83AddImmediate(0x60,q+8),length=2);p.hook(q+8,Store('serial_send_data',q+10),length=2);p.hook(q+10,Read('connection_status',q+12),length=2);p.hook(q+12,Sm83CpImmediate(2,q+14),length=2);p.hook(q+18,Store('serial_control',q+20),length=2);p.hook(q+20,Read('serial_receive_data',q+22),length=2);p.hook(q+22,Store('temp_receive_data',q+25),length=3);p.hook(q+25,Sm83AndImmediate(0xf0,q+27),length=2);p.hook(q+27,Sm83CpImmediate(0x60,q+29),length=2);p.hook(q+30,XorA(q+31),length=1);p.hook(q+31,Store('serial_receive_data',q+33),length=2);p.hook(q+33,Read('temp_receive_data',q+36),length=3);p.hook(q+36,Sm83AndImmediate(0x0f,q+38),length=2);p.hook(q+38,Store('receive_data',q+41),length=3);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');return [E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[k] for k in KEYS)),constraints=tuple(x.solver.constraints)) for x in collect_returns(p,s,RETURN)]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_serial_exchange_nybble');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('serial_exchange_nybble');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'Serial_ExchangeNybble');assert linked_bytes(ROM,l,42)==bytes.fromhex('cdd722fa42ccc660e0acf0aafe0220043e81e002f0adea3dcce6f0fe60c0afe0adfa3dcce60fea3eccc9')
