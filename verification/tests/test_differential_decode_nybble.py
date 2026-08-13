from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddRegister,Sm83AndImmediate,Sm83BitRegister,Sm83IncRegister,Sm83SrlRegister,Sm83SwapRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff
NAMES=('flipped','table0_low','table0_high','table1_low','table1_high','fetched')
class Load(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)
class AndA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.f=claripy.BVV(0x10,8)|claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8));self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs():
 i=symbolic_registers('differential_decode')
 for n in NAMES:i[n]=claripy.BVS('differential_decode_'+n,8)
 return i
def assembly(i):
 l=symbol_location(SYMBOLS,'DifferentialDecodeNybble');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q})
 p.hook(q,Sm83SrlRegister('a',q+2),length=2);p.hook(q+9,Load('flipped',q+12),length=3);p.hook(q+12,AndA(q+13),length=1);p.hook(q+15,Sm83BitRegister(3,'e',q+17),length=2);p.hook(q+19,Sm83BitRegister(0,'e',q+21),length=2)
 for off,key,nxt in ((24,'table0_low',27),(28,'table0_high',31),(33,'table1_low',36),(37,'table1_high',40),(47,'fetched',48)):p.hook(q+off,Load(key,q+nxt),length=nxt-off)
 p.hook(q+42,Sm83AddRegister('l',q+43),length=1);p.hook(q+46,Sm83IncRegister('h',q+47),length=1);p.hook(q+48,Sm83BitRegister(0,'c',q+50),length=2);p.hook(q+52,Sm83SwapRegister('a',q+54),length=2);p.hook(q+54,Sm83AndImmediate(0x0f,q+56),length=2)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for n in NAMES:s.globals[n]=i[n]
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');return [E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[n] for n in NAMES)),constraints=tuple(x.solver.constraints)) for x in collect_returns(p,s,RETURN)]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_differential_decode_nybble');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,6),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs();assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'DifferentialDecodeNybble');assert linked_bytes(ROM,l,58)==bytes.fromhex('cb3f0e0030020e016ffaaad0a72804cb5b1802cb435d2009fab1d06ffab2d01807fab3d06ffab4d0677b856f3001247ecb412002cb37e60f5fc9')
