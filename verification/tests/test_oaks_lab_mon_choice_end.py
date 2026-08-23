from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;DONE=0xEFFF
EXPECTED=bytes.fromhex('c3d724')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;tse:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class ATail(angr.SimProcedure):
 """Proven TextScriptEnd boundary at the tail target: snapshot hand-off
 registers, apply the shared arbitrary proven transition, stop."""
 def run(self):
  r=assembly_registers(self.state);self.state.globals['tse']=claripy.Concat(*(r[x] for x in REGISTERS))
  for x in REGISTERS:
   v=self.state.globals[f'e_out_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  self.jump(DONE)
class NTail(angr.SimProcedure):
 def run(self):
  s=self.state.regs.rdi
  self.state.globals['tse']=self.state.memory.load(s,8)
  self.state.memory.store(s,claripy.Concat(*(self.state.globals[f'e_out_{x}'] for x in REGISTERS)))
  ra=self.state.memory.load(self.state.regs.sp,8,endness='Iend_LE');self.state.regs.sp=self.state.regs.sp+8;self.jump(ra)
def inputs(p):
 v=symbolic_registers(p)
 for x in REGISTERS:v[f'e_out_{x}']=claripy.Concat(claripy.BVS(f'{p}_e_out_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(f'{p}_e_out_{x}',8)
 return v
def setup(s,v):
 s.globals['tse']=claripy.BVV(0,64)
 for key,val in v.items():
  if key.startswith('e_out_'):s.globals[key]=val
def assembly(v):
 l=symbol_location(SYMS,'OaksLabMonChoiceEnd');t=symbol_location(SYMS,'TextScriptEnd');assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(t.address,ATail())
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v)
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=8);assert not m.errored and len(m.found)==1
 return [E(**assembly_registers(x),tse=x.globals['tse'],constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_oaks_lab_mon_choice_end');t=p.loader.find_symbol('port_text_script_end');assert f and t
 p.hook(t.rebased_addr,NTail())
 s=p.factory.call_state(f.rebased_addr,NS);store_native_registers(s,NS,v);setup(s,v)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1
 return [E(**native_registers(x,NS),tse=x.globals['tse'],constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_oaks_lab_mon_choice_end_pathwise_equivalence():
 v=inputs('oaks_lab_mon_choice_end');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'tse'))
