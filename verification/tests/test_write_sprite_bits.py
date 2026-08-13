from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate,Sm83OrRegister,Sm83SlaRegister,Sm83SwapRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff
NAMES=('offset','pointer_low','pointer_high','pointed')
class Load(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)
class AndA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.f=claripy.BVV(0x10,8)|claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8));self.jump(self.n)
class Rrc(angr.SimProcedure):
 def __init__(self,r,n):super().__init__();self.r=r;self.n=n
 def run(self):
  v=getattr(self.state.regs,self.r);z=claripy.RotateRight(v,1);setattr(self.state.regs,self.r,z);self.state.regs.f=claripy.If(z==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.ZeroExt(7,v[0]);self.jump(self.n)
class Store(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['pointed']=self.state.regs.a;self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs():
 i=symbolic_registers('write_sprite_bits')
 for n in NAMES:i[n]=claripy.BVS('write_sprite_bits_'+n,8)
 return i
def assembly(i):
 l=symbol_location(SYMBOLS,'WriteSpriteBitsToBuffer');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q})
 p.hook(q+1,Load('offset',q+4),length=3);p.hook(q+4,AndA(q+5),length=1);p.hook(q+7,Sm83CpImmediate(2,q+9),length=2);p.hook(q+13,Rrc('e',q+15),length=2);p.hook(q+15,Rrc('e',q+17),length=2);p.hook(q+19,Sm83SlaRegister('e',q+21),length=2);p.hook(q+21,Sm83SlaRegister('e',q+23),length=2);p.hook(q+25,Sm83SwapRegister('e',q+27),length=2);p.hook(q+27,Load('pointer_low',q+30),length=3);p.hook(q+31,Load('pointer_high',q+34),length=3);p.hook(q+35,Load('pointed',q+36),length=1);p.hook(q+36,Sm83OrRegister('e',q+37),length=1);p.hook(q+37,Store(q+38),length=1)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for n in NAMES:s.globals[n]=i[n]
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');return [E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[n] for n in NAMES)),constraints=tuple(x.solver.constraints)) for x in collect_returns(p,s,RETURN)]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_write_sprite_bits_to_buffer');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,4),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs();assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'WriteSpriteBitsToBuffer');assert linked_bytes(ROM,l,39)==bytes.fromhex('5ffaa7d0a72814fe023808280ccb0bcb0b1808cb23cb231802cb33faadd06ffaaed0677eb377c9')
