from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddRegister,Sm83DecRegister,Sm83IncRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xefff;KEYS=('background_palette_index','background_palette_data','fetched_index','fetched_palette')
class Read(angr.SimProcedure):
 def __init__(self,key,n,hli=False):super().__init__();self.key=key;self.n=n;self.hli=hli
 def run(self):self.state.regs.a=self.state.globals[self.key];self.state.regs.hl=self.state.regs.hl+(1 if self.hli else 0);self.jump(self.n)  # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.jump(self.n)  # type: ignore[override]
class Bound(angr.SimProcedure):
 def __init__(self,step=False):super().__init__();self.step=step
 def run(self):self.state.globals['result']=claripy.If(self.state.regs.c==0,claripy.BVV(1,8),claripy.BVV(0,8)) if self.step else claripy.BVV(2,8);self.jump(DONE)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 return i
def assembly(i,step):
 l=symbol_location(SYMBOLS,'InitCGBPalettes');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address
 if not step:start=q;p.hook(q+2,Store('background_palette_index',q+4),length=2);p.hook(q+7,Bound(),length=0)
 else:
  start=q+7;p.hook(q+7,Read('fetched_index',q+8,hli=True),length=1);p.hook(q+9,Sm83AddRegister('a',q+10),length=1);p.hook(q+10,Sm83AddRegister('a',q+11),length=1);p.hook(q+11,Sm83AddRegister('a',q+12),length=1);p.hook(q+15,Sm83AddRegister('e',q+16),length=1);p.hook(q+18,Sm83IncRegister('d',q+19),length=1);p.hook(q+19,Read('fetched_palette',q+20),length=1);p.hook(q+20,Store('background_palette_data',q+22),length=2);p.hook(q+22,Sm83DecRegister('c',q+23),length=1);p.hook(q+23,Bound(True),length=2)
 s=p.factory.blank_state(addr=start);set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
 s.globals['result']=claripy.BVV(2,8);m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=10);return [E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[k] for k in KEYS)),result=x.globals['result'],constraints=tuple(x.solver.constraints)) for x in m.found]
def native(i,step):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);name='port_init_cgb_palettes_step' if step else 'port_init_cgb_palettes_begin';fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),result=x.regs.rax[7:0] if step else claripy.BVV(2,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('step',(False,True))
def test_equivalence(step):
 i=inputs('cgb_'+str(step));assert_pathwise_equivalent(assembly(i,step),native(i,step),(*REGISTERS,'memory','result'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'InitCGBPalettes');assert linked_bytes(ROM,l,26)==bytes.fromhex('3e80e068230e202a23878787116066833001141ae0690d20eec9');assert symbol_location(SYMBOLS,'SuperPalettes').address==0x6660
