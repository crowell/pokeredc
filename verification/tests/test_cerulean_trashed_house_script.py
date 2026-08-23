from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x400000;DONE=0xEFFF
EXPECTED=linked_bytes(ROM,symbol_location(SYMS,'CeruleanTrashedHouse_Script'),4)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;control:claripy.ast.BV;wait:claripy.ast.BV;at:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class ATBDBoundary(angr.SimProcedure):
 def run(self):
  r=assembly_registers(self.state);m=self.state.memory
  self.state.globals['at']=claripy.Concat(*(r[x] for x in REGISTERS),m.load(0xCF0C,1),m.load(0xCC3C,1))
  for x in REGISTERS:
   v=self.state.globals['at_out_'+x];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  m.store(0xCF0C,self.state.globals['at_out_control']);m.store(0xCC3C,self.state.globals['at_out_wait'])
  self.jump(DONE)
class NATB(angr.SimProcedure):
 def run(self):
  s=self.state.regs.rdi;mm=self.state.memory
  self.state.globals['at']=claripy.Concat(mm.load(s,8),mm.load(s+8,1),mm.load(s+9,1))
  mm.store(s,claripy.Concat(*(self.state.globals[f'at_out_{x}'] for x in REGISTERS)))
  mm.store(s+8,self.state.globals['at_out_control']);mm.store(s+9,self.state.globals['at_out_wait'])
  ra=mm.load(self.state.regs.sp,8,endness='Iend_LE');self.state.regs.sp=self.state.regs.sp+8;self.jump(ra)

def inputs(p):
 v=symbolic_registers(p)
 for x in REGISTERS:v['at_out_'+x]=claripy.Concat(claripy.BVS(p+'_at_out_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(p+'_at_out_'+x,8)
 v['at_out_control']=claripy.BVS(p+'_at_out_control',8);v['at_out_wait']=claripy.BVS(p+'_at_out_wait',8)
 v['control_in']=claripy.BVS(p+'_control_in',8);v['wait_in']=claripy.BVS(p+'_wait_in',8)
 return v
def setup(s,v):
 s.globals['at']=claripy.BVV(0,10*8)
 for key,val in v.items():
  if key.startswith('at_out_'):s.globals[key]=val
def store_memory(s,v,base=0):
 s.memory.store(base+0xCF0C,v['control_in']);s.memory.store(base+0xCC3C,v['wait_in'])
def assembly(v):
 l=symbol_location(SYMS,'CeruleanTrashedHouse_Script');assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(l.address if False else symbol_location(SYMS,'EnableAutoTextBoxDrawing').address,ATBDBoundary(),length=3)
 s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v);setup(s,v);store_memory(s,v)
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=8);assert not m.errored and len(m.found)==1
 return [E(**assembly_registers(x),control=x.memory.load(0xCF0C,1),wait=x.memory.load(0xCC3C,1),at=x.globals['at'],constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_cerulean_trashed_house_script');t=p.loader.find_symbol('port_enable_auto_text_box_drawing');assert f and t
 p.hook(t.rebased_addr,NATB())
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v);store_memory(s,v,NM)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1
 return [E(**native_registers(x,NS),control=x.memory.load(NM+0xCF0C,1),wait=x.memory.load(NM+0xCC3C,1),at=x.globals['at'],constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_cerulean_trashed_house_script_pathwise_equivalence():
 v=inputs('cerulean_trashed_house_script');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'control','wait','at'))
