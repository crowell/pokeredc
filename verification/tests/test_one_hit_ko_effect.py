from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83DecRegister,Sm83LoadAAtHlDecrement,Sm83LoadAHighImmediate,Sm83SbcRegister,Sm83StoreAAtHlIncrement,Sm83StoreAImmediate,Sm83SubRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff
WHOSE=0xfff3;PLAYER_HI=0xd029;PLAYER_LO=0xd02a;ENEMY_HI=0xcffa;ENEMY_LO=0xcffb;DAMAGE_HI=0xd0d7;DAMAGE_LO=0xd0d8;CRITICAL=0xd05e;MISSED=0xd05f
KEYS=('whose_turn','player_speed_high','player_speed_low','enemy_speed_high','enemy_speed_low','damage_high','damage_low','critical_or_ohko','move_missed');ADDRS=(WHOSE,PLAYER_HI,PLAYER_LO,ENEMY_HI,ENEMY_LO,DAMAGE_HI,DAMAGE_LO,CRITICAL,MISSED)
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
 l=symbol_location(SYMBOLS,'OneHitKOEffect_');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address
 p.hook(q+3,XorA(q+4),length=1);p.hook(q+4,Sm83StoreAAtHlIncrement(q+5),length=1);p.hook(q+6,Sm83DecRegister('a',q+7),length=1);p.hook(q+7,Sm83StoreAImmediate(CRITICAL,q+10),length=3);p.hook(q+16,Sm83LoadAHighImmediate(0xf3,q+18),length=2);p.hook(q+18,Sm83AndImmediate(0xff,q+19),length=1);p.hook(q+30,Sm83LoadAAtHlDecrement(q+31),length=1);p.hook(q+31,Sm83SubRegister('b',q+32),length=1);p.hook(q+35,Sm83SbcRegister('b',q+36),length=1);p.hook(q+43,Sm83StoreAAtHlIncrement(q+44),length=1);p.hook(q+47,Sm83StoreAImmediate(CRITICAL,q+50),length=3);p.hook(q+53,Sm83StoreAImmediate(MISSED,q+56),length=3)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for a,k in zip(ADDRS,KEYS):s.memory.store(a,i[k])
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');ends=collect_returns(p,s,RETURN)
 return [E(**assembly_registers(x),memory=claripy.Concat(*(x.memory.load(a,1) for a in ADDRS)),constraints=tuple(x.solver.constraints)) for x in ends]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_one_hit_ko_effect');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('ohko');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'OneHitKOEffect_');assert linked_bytes(ROM,l,57)==bytes.fromhex('21d7d0af22773dea5ed0212ad011fbcff0f3a7280621fbcf112ad01a1b473a901a477e98380d21d7d03eff22773e02ea5ed0c93e01ea5fd0c9')
