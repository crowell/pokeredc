from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83DecRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xefff
class XorA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=claripy.BVV(0,8);self.state.regs.f=claripy.BVV(0x40,8);self.jump(self.n)  # type: ignore[override]
class Fetch(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=self.state.globals['fetched'];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['written']=self.state.regs.a;self.jump(self.n)  # type: ignore[override]
class Bound(angr.SimProcedure):
 def __init__(self,reg=None):super().__init__();self.reg=reg
 def run(self):self.state.globals['result']=claripy.If(getattr(self.state.regs,self.reg)==0,claripy.BVV(1,8),claripy.BVV(0,8)) if self.reg else claripy.BVV(2,8);self.jump(DONE)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p);i['fetched']=claripy.BVS(p+'_fetched',8);i['written']=claripy.BVS(p+'_written',8);return i
def assembly(i,phase):
 l=symbol_location(SYMBOLS,'CopySGBBorderTiles');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address
 if phase=='begin':start=q;p.hook(q+2,Bound(),length=0)
 elif phase=='copy_begin':start=q+2;p.hook(q+4,Bound(),length=0)
 elif phase=='copy_step':start=q+4;p.hook(q+4,Fetch(q+5),length=1);p.hook(q+5,Store(q+6),length=1);p.hook(q+7,Sm83DecRegister('c',q+8),length=1);p.hook(q+8,Bound('c'),length=2)
 elif phase=='zero_begin':start=q+10;p.hook(q+12,XorA(q+13),length=1);p.hook(q+13,Bound(),length=0)
 elif phase=='zero_step':start=q+13;p.hook(q+13,Store(q+14),length=1);p.hook(q+15,Sm83DecRegister('c',q+16),length=1);p.hook(q+16,Bound('c'),length=2)
 else:start=q+18;p.hook(q+18,Sm83DecRegister('b',q+19),length=1);p.hook(q+19,Bound('b'),length=2)
 s=p.factory.blank_state(addr=start);set_assembly_registers(s,i);s.globals['fetched']=i['fetched'];s.globals['written']=i['written'];s.globals['result']=claripy.BVV(2,8);m=p.factory.simulation_manager(s);m.explore(find=DONE);return [E(**assembly_registers(x),memory=claripy.Concat(x.globals['fetched'],x.globals['written']),result=x.globals['result'],constraints=tuple(x.solver.constraints)) for x in m.found]
def native(i,phase):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);name='port_copy_sgb_border_tiles_'+phase;fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(i['fetched'],i['written']));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,2),result=x.regs.rax[7:0] if phase.endswith('step') else claripy.BVV(2,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('phase',('begin','copy_begin','copy_step','zero_begin','zero_step','tile_step'))
def test_phase(phase):
 i=inputs('sgb_'+phase);assert_pathwise_equivalent(assembly(i,phase),native(i,phase),(*REGISTERS,'memory','result'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'CopySGBBorderTiles');assert linked_bytes(ROM,l,22)==bytes.fromhex('06800e102a12130d20fa0e10af12130d20fb0520edc9')
