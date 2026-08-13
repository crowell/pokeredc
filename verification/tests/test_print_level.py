from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate,Sm83IncRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;NATIVE_CALLBACK=0x100100;NATIVE_GLOBALS=0x100200;DONE=0xefff;KEYS=('loaded_level','destination_tile','temp_byte','dispatched')
class StoreTileHli(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['destination_tile']=self.state.regs.a;self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
class ReadLevel(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=self.state.globals['loaded_level'];self.jump(self.n)  # type: ignore[override]
class StoreTemp(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['temp_byte']=self.state.regs.a;self.jump(self.n)  # type: ignore[override]
class Boundary(angr.SimProcedure):
 def __init__(self,full):super().__init__();self.full=full
 def run(self):
  self.state.globals['dispatched']=claripy.BVV(1,8)
  if self.full:
   cb=self.state.globals['callback']
   for r in REGISTERS:setattr(self.state.regs,r,sm83_flags_to_z80(cb[r]) if r=='f' else cb[r])
   for k in KEYS[:3]:self.state.globals[k]=cb[k]
  self.jump(DONE)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 for r,v in symbolic_registers(p+'_callback').items():i['callback_'+r]=v
 for k in KEYS[:3]:i['callback_'+k]=claripy.BVS(f'{p}_callback_{k}',8)
 return i
def assembly(i,full):
 l=symbol_location(SYMBOLS,'PrintLevel');target=symbol_location(SYMBOLS,'PrintNumber').address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q+2,StoreTileHli(q+3),length=1);p.hook(q+5,ReadLevel(q+8),length=3);p.hook(q+8,Sm83CpImmediate(100,q+10),length=2);p.hook(q+13,Sm83IncRegister('c',q+14),length=1);p.hook(q+24,StoreTemp(q+27),length=3);p.hook(target,Boundary(full));s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
 s.globals['callback']={r:i['callback_'+r] for r in REGISTERS}|{k:i['callback_'+k] for k in KEYS[:3]};m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=10);assert not m.errored
 return [E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[k] for k in KEYS)),constraints=tuple(x.solver.constraints)) for x in m.found]
def native(i,full):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);name='port_print_level' if full else 'port_print_level_begin';fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE,NATIVE_CALLBACK,NATIVE_GLOBALS) if full else p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)))
 if full:
  store_native_registers(s,NATIVE_CALLBACK,{r:i['callback_'+r] for r in REGISTERS});s.memory.store(NATIVE_GLOBALS,claripy.Concat(*(i['callback_'+k] for k in KEYS[:3])))
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('full',(False,True))
def test_equivalence(full):
 i=inputs('print_level_'+str(full));assert_pathwise_equivalent(assembly(i,full),native(i,full),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'PrintLevel');assert linked_bytes(ROM,l,16)==bytes.fromhex('3e6e220e02fab9cffe64380c2b0c1808');c=symbol_location(SYMBOLS,'PrintLevelCommon');assert linked_bytes(ROM,c,11)==bytes.fromhex('ea1ed1111ed10641c35f3c');assert symbol_location(SYMBOLS,'wLoadedMonLevel').address==0xcfb9;assert symbol_location(SYMBOLS,'wTempByteValue').address==0xd11e
