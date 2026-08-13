from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AddImmediate,Sm83CpImmediate,Sm83LoadAImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff
CURRENT_MAP=0xd35e;OFFSET=0xcd3d;FACING=0xcd3f;SCREEN_Y=0xcd40;SCREEN_X=0xcd41;KEYS=('current_map','trainer_offset','trainer_facing','fetched_y','fetched_x','trainer_screen_y','trainer_screen_x')
class Fetch(angr.SimProcedure):
 def __init__(self,n,key):super().__init__();self.n=n;self.key=key
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)  # type: ignore[override]
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
 l=symbol_location(SYMBOLS,'CheckPlayerIsInFrontOfSprite');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address
 for o,a in ((0,CURRENT_MAP),(8,OFFSET),(30,OFFSET),(46,FACING),(53,SCREEN_Y),(66,SCREEN_Y),(79,SCREEN_X),(88,SCREEN_X)):p.hook(q+o,Sm83LoadAImmediate(a,q+o+3),length=3)
 for o,v in ((3,0x53),(21,0xfc),(49,0),(56,0x3c),(62,4),(69,0x3c),(75,8),(82,0x40),(91,0x40)):p.hook(q+o,Sm83CpImmediate(v,q+o+2),length=2)
 p.hook(q+11,Sm83AddImmediate(4,q+13),length=2);p.hook(q+19,Sm83AddHlRegisterPair('de',q+20),length=1);p.hook(q+20,Fetch(q+21,'fetched_y'),length=1);p.hook(q+27,Sm83StoreAImmediate(SCREEN_Y,q+30),length=3);p.hook(q+33,Sm83AddImmediate(6,q+35),length=2);p.hook(q+41,Sm83AddHlRegisterPair('de',q+42),length=1);p.hook(q+42,Fetch(q+43,'fetched_x'),length=1);p.hook(q+43,Sm83StoreAImmediate(SCREEN_X,q+46),length=3);p.hook(q+99,XorA(q+100),length=1);p.hook(q+100,Sm83StoreAImmediate(OFFSET,q+103),length=3)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for a,k in ((CURRENT_MAP,'current_map'),(OFFSET,'trainer_offset'),(FACING,'trainer_facing'),(SCREEN_Y,'trainer_screen_y'),(SCREEN_X,'trainer_screen_x')):s.memory.store(a,i[k])
 for k in KEYS:s.globals[k]=i[k]
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');ends=collect_returns(p,s,RETURN)
 return [E(**assembly_registers(x),memory=claripy.Concat(x.memory.load(CURRENT_MAP,1),x.memory.load(OFFSET,1),x.memory.load(FACING,1),i['fetched_y'],i['fetched_x'],x.memory.load(SCREEN_Y,1),x.memory.load(SCREEN_X,1)),constraints=tuple(x.solver.constraints)) for x in ends]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_check_player_is_in_front_of_sprite');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('trainer_front');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'CheckPlayerIsInFrontOfSprite');assert linked_bytes(ROM,l,104)==bytes.fromhex('fa5ed3fe53ca426afa3dcdc60416005f2100c1197efefc20023e0cea40cdfa3dcdc60616005f2100c1197eea41cdfa3fcdfe002009fa40cdfe3c38231825fe042009fa40cdfe3c30161818fe082009fa41cdfe403009180bfa41cdfe4030043eff1801afea3dcdc9')
