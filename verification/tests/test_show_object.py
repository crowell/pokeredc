from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;NATIVE_CALLBACKS=0x100100;NATIVE_INDICES=0x100200;DONE=0xefff
class ReadIndex(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=self.state.globals['toggleable_object_index'];self.jump(self.n)  # type: ignore[override]
class Boundary(angr.SimProcedure):
 def __init__(self,stage,n=None):super().__init__();self.stage=stage;self.n=n
 def run(self):
  self.state.globals['stage']=claripy.BVV(self.stage,8)
  if self.stage>1:
   cb=self.state.globals['callbacks'][self.stage-2]
   for r in REGISTERS:setattr(self.state.regs,r,sm83_flags_to_z80(cb[r]) if r=='f' else cb[r])
   self.state.globals['toggleable_object_index']=cb['toggleable_object_index']
  self.jump(DONE if self.n is None else self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p);i['toggleable_object_index']=claripy.BVS(p+'_index',8);i['stage']=claripy.BVS(p+'_stage',8)
 for n in range(2):
  for r,v in symbolic_registers(f'{p}_callback{n}').items():i[f'callback{n}_{r}']=v
  i[f'callback{n}_toggleable_object_index']=claripy.BVS(f'{p}_callback{n}_index',8)
 return i
def assembly(i,full):
 l=symbol_location(SYMBOLS,'ShowObject');update=symbol_location(SYMBOLS,'UpdateSprites').address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q+3,ReadIndex(q+6),length=3)
 if full:p.hook(q+9,Boundary(2,q+12),length=3);p.hook(update,Boundary(3))
 else:p.hook(q+9,Boundary(1),length=3)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.globals['toggleable_object_index']=i['toggleable_object_index'];s.globals['stage']=claripy.BVV(0,8);s.globals['callbacks']=[{r:i[f'callback{n}_{r}'] for r in REGISTERS}|{'toggleable_object_index':i[f'callback{n}_toggleable_object_index']} for n in range(2)];m=p.factory.simulation_manager(s);m.explore(find=DONE);return [E(**assembly_registers(x),memory=claripy.Concat(x.globals['toggleable_object_index'],x.globals['stage']),constraints=tuple(x.solver.constraints)) for x in m.found]
def native(i,full):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);name='port_show_object' if full else 'port_show_object_begin';fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE,NATIVE_CALLBACKS,NATIVE_INDICES) if full else p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(i['toggleable_object_index'],i['stage']))
 if full:
  for n in range(2):store_native_registers(s,NATIVE_CALLBACKS+n*8,{r:i[f'callback{n}_{r}'] for r in REGISTERS});s.memory.store(NATIVE_INDICES+n,i[f'callback{n}_toggleable_object_index'])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,2),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('full',(False,True))
def test_equivalence(full):
 i=inputs('show_object_'+str(full));assert_pathwise_equivalent(assembly(i,full),native(i,full),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'ShowObject');assert linked_bytes(ROM,l,15)==bytes.fromhex('21a6d5fa4dcc4f0600cde671c32924');assert symbol_location(SYMBOLS,'wToggleableObjectIndex').address==0xcc4d
