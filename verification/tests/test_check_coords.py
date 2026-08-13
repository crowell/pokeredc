from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83CpImmediate,Sm83CpRegister,Sm83Scf
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xefff;KEYS=('coord_index','fetched_y','fetched_x')
class XorA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=claripy.BVV(0,8);self.state.regs.f=claripy.BVV(0x40,8);self.jump(self.n)  # type: ignore[override]
class StoreIndex(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['coord_index']=self.state.regs.a;self.jump(self.n)  # type: ignore[override]
class IncIndex(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  old=self.state.globals['coord_index'];new=old+1;flags=self.state.regs.f&1;flags|=claripy.If(new==0,claripy.BVV(0x40,8),claripy.BVV(0,8));flags|=claripy.If((old&0xf)==0xf,claripy.BVV(0x10,8),claripy.BVV(0,8));self.state.globals['coord_index']=new;self.state.regs.f=flags;self.jump(self.n)  # type: ignore[override]
class FetchY(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals['iterated']:
   self.state.globals['result']=claripy.BVV(1,8);self.jump(DONE);return  # type: ignore[override]
  self.state.globals['iterated']=True;self.state.regs.a=self.state.globals['fetched_y'];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
class FetchX(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=self.state.globals['fetched_x'];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
class Finish(angr.SimProcedure):
 def __init__(self,result):super().__init__();self.result=result
 def run(self):self.state.globals['result']=claripy.BVV(self.result,8);self.jump(DONE)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 return i
def project():
 l=symbol_location(SYMBOLS,'CheckCoords');return l,angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
def endpoint(x):return E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[k] for k in KEYS)),result=x.globals['result'],constraints=tuple(x.solver.constraints))
def begin(i):
 l,p=project();q=l.address;p.hook(q,XorA(q+1),length=1);p.hook(q+1,StoreIndex(q+4),length=3);p.hook(q+4,Finish(3),length=0);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
 s.globals['result']=claripy.BVV(3,8);m=p.factory.simulation_manager(s);m.explore(find=DONE);return [endpoint(x) for x in m.found]
def step(i):
 l,p=project();q=l.address;p.hook(q+4,FetchY(q+5),length=1);p.hook(q+5,Sm83CpImmediate(0xff,q+7),length=2);p.hook(q+13,IncIndex(q+14),length=1);p.hook(q+15,Sm83CpRegister('b',q+16),length=1);p.hook(q+21,FetchX(q+22),length=1);p.hook(q+22,Sm83CpRegister('c',q+23),length=1);p.hook(q+25,Sm83Scf(q+26),length=1);p.hook(q+26,Finish(2),length=1);p.hook(q+27,Sm83AndImmediate(0xff,q+28),length=1);p.hook(q+28,Finish(0),length=1);s=p.factory.blank_state(addr=q+4);set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
 s.globals['iterated']=False;s.globals['result']=claripy.BVV(0,8);m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=10);return [endpoint(x) for x in m.found]
def native(symbol,i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(symbol);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),result=x.regs.rax[7:0] if symbol.endswith('step') else claripy.BVV(3,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_begin():
 i=inputs('check_coords_begin');assert_pathwise_equivalent(begin(i),native('port_check_coords_begin',i),(*REGISTERS,'memory','result'))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_step():
 i=inputs('check_coords_step');assert_pathwise_equivalent(step(i),native('port_check_coords_step',i),(*REGISTERS,'memory','result'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'CheckCoords');assert linked_bytes(ROM,l,29)==bytes.fromhex('afea3dcd2afeff2812e5213dcd34e1b828032318ef2ab920eb37c9a7c9')
