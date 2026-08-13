from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AdcRegister,Sm83AddRegister,Sm83LoadAHighImmediate,Sm83RrRegister,Sm83SrlRegister,Sm83StoreAHighImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff;HIGH=0xff97;LOW=0xff98
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p);i['high']=claripy.BVS(p+'_high',8);i['low']=claripy.BVS(p+'_low',8);return i
def assembly(i):
 l=symbol_location(SYMBOLS,'BoostExp');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q,Sm83LoadAHighImmediate(0x97,q+2),length=2);p.hook(q+3,Sm83LoadAHighImmediate(0x98,q+5),length=2);p.hook(q+6,Sm83SrlRegister('b',q+8),length=2);p.hook(q+8,Sm83RrRegister('c',q+10),length=2);p.hook(q+10,Sm83AddRegister('c',q+11),length=1);p.hook(q+11,Sm83StoreAHighImmediate(0x98,q+13),length=2);p.hook(q+13,Sm83LoadAHighImmediate(0x97,q+15),length=2);p.hook(q+15,Sm83AdcRegister('b',q+16),length=1);p.hook(q+16,Sm83StoreAHighImmediate(0x97,q+18),length=2);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.memory.store(HIGH,i['high']);s.memory.store(LOW,i['low']);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');ends=collect_returns(p,s,RETURN)
 return [E(**assembly_registers(x),memory=claripy.Concat(x.memory.load(HIGH,1),x.memory.load(LOW,1)),constraints=tuple(x.solver.constraints)) for x in ends]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_boost_exp');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(i['high'],i['low']));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,2),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('boost_exp');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'BoostExp');assert linked_bytes(ROM,l,19)==bytes.fromhex('f09747f0984fcb38cb1981e098f09788e097c9')
