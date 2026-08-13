from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83LoadAImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff;FACING=0xc109;ADJUST=0xd08a
KEYS=('facing_direction','coordinate_adjustment','fetched_adjustment','fetched_oam_offset','fetched_pointer_low','fetched_pointer_high')
class Fetch(angr.SimProcedure):
 def __init__(self,n,key,register='a',inc=False):super().__init__();self.n=n;self.key=key;self.register=register;self.inc=inc
 def run(self):setattr(self.state.regs,self.register,self.state.globals[self.key]);self.state.regs.hl=self.state.regs.hl+(1 if self.inc else 0);self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 return i
def assembly(i):
 l=symbol_location(SYMBOLS,'GetMoveBoulderDustFunctionPointer');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address
 p.hook(q,Sm83LoadAImmediate(FACING,q+3),length=3);p.hook(q+9,Sm83AddHlRegisterPair('bc',q+10),length=1);p.hook(q+10,Fetch(q+11,'fetched_adjustment',inc=True),length=1);p.hook(q+11,Sm83StoreAImmediate(ADJUST,q+14),length=3);p.hook(q+14,Fetch(q+15,'fetched_oam_offset',inc=True),length=1);p.hook(q+16,Fetch(q+17,'fetched_pointer_low',inc=True),length=1);p.hook(q+17,Fetch(q+18,'fetched_pointer_high','h'),length=1);p.hook(q+25,Sm83AddHlRegisterPair('de',q+26),length=1)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.memory.store(FACING,i['facing_direction']);s.memory.store(ADJUST,i['coordinate_adjustment'])
 for k in KEYS:s.globals[k]=i[k]
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');ends=collect_returns(p,s,RETURN);return [E(**assembly_registers(x),memory=claripy.Concat(x.memory.load(FACING,1),x.memory.load(ADJUST,1),*(i[k] for k in KEYS[2:])),constraints=tuple(x.solver.constraints)) for x in ends]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_get_move_boulder_dust_function_pointer');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('boulder_pointer');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'GetMoveBoulderDustFunctionPointer');assert linked_bytes(ROM,l,30)==bytes.fromhex('fa09c121b05f4f0600092aea8ad02a5f2a666fe52190c31600195d54e1c9')
