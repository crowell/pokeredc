from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AddRegister,Sm83AndImmediate,Sm83LoadAImmediate,Sm83SrlRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff;WHICH=0xcd50
KEYS=('y_pixels','x_pixels','direction','which_offsets','fetched_x_offset','fetched_y_offset')
class Fetch(angr.SimProcedure):
 def __init__(self,n,key,register='a',inc=False):super().__init__();self.n=n;self.key=key;self.register=register;self.inc=inc
 def run(self):setattr(self.state.regs,self.register,self.state.globals[self.key]);self.state.regs.hl=self.state.regs.hl+(1 if self.inc else 0);self.jump(self.n)  # type: ignore[override]
class IncHl(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 return i
def assembly(i):
 l=symbol_location(SYMBOLS,'GetCutOrBoulderDustAnimationOffsets');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address
 p.hook(q+3,Fetch(q+4,'y_pixels',inc=True),length=1);p.hook(q+5,IncHl(q+6),length=1);p.hook(q+6,Fetch(q+7,'x_pixels',inc=True),length=1);p.hook(q+8,IncHl(q+9),length=1);p.hook(q+9,IncHl(q+10),length=1);p.hook(q+10,Fetch(q+11,'direction'),length=1);p.hook(q+11,Sm83SrlRegister('a',q+13),length=2);p.hook(q+16,Sm83LoadAImmediate(WHICH,q+19),length=3);p.hook(q+19,Sm83AndImmediate(0xff,q+20),length=1);p.hook(q+28,Sm83AddHlRegisterPair('de',q+29),length=1);p.hook(q+29,Fetch(q+30,'fetched_x_offset','e'),length=1);p.hook(q+30,IncHl(q+31),length=1);p.hook(q+31,Fetch(q+32,'fetched_y_offset','d'),length=1);p.hook(q+33,Sm83AddRegister('d',q+34),length=1);p.hook(q+36,Sm83AddRegister('e',q+37),length=1)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.memory.store(WHICH,i['which_offsets'])
 for k in KEYS:s.globals[k]=i[k]
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');ends=collect_returns(p,s,RETURN);mem=claripy.Concat(*(i[k] for k in KEYS));return [E(**assembly_registers(x),memory=mem,constraints=tuple(x.solver.constraints)) for x in ends]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_get_cut_or_boulder_dust_animation_offsets');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('dust_offsets');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'GetCutOrBoulderDustAnimationOffsets');assert linked_bytes(ROM,l,39)==bytes.fromhex('2104c12a47232a4f23237ecb3f5f1600fa50cda7218f702803219770195e235678824779834fc9')
