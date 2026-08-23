from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x400000;DONE=0xEFFF;STACK=0xD000;RETURN=0xFFFF
EXPECTED=bytes.fromhex('c33c3c')
W_CONTROL=0xCF0C;W_DO_NOT_WAIT=0xCC3C
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;control:claripy.ast.BV;wait:claripy.ast.BV;call:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Callee(angr.SimProcedure):
 """Proven EnableAutoTextBoxDrawing boundary at its entry: snapshot the tail
 hand-off (registers plus both control bytes), apply the shared arbitrary
 proven transition, stop."""
 def run(self):
  r=assembly_registers(self.state);m=self.state.memory
  self.state.globals['call']=claripy.Concat(*(r[x] for x in REGISTERS),m.load(W_CONTROL,1),m.load(W_DO_NOT_WAIT,1))
  for x in REGISTERS:
   v=self.state.globals[f'out_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  m.store(W_CONTROL,self.state.globals['out_control']);m.store(W_DO_NOT_WAIT,self.state.globals['out_wait'])
  self.jump(DONE)
class NCallee(angr.SimProcedure):
 """10-byte auto_text_box_state arrives via rdi; explicit RET."""
 def run(self):
  s=self.state.regs.rdi;mm=self.state.memory
  self.state.globals['call']=claripy.Concat(mm.load(s,8),mm.load(s+8,1),mm.load(s+9,1))
  mm.store(s,claripy.Concat(*(self.state.globals[f'out_{x}'] for x in REGISTERS)))
  mm.store(s+8,self.state.globals['out_control']);mm.store(s+9,self.state.globals['out_wait'])
  ra=mm.load(self.state.regs.sp,8,endness='Iend_LE');self.state.regs.sp=self.state.regs.sp+8;self.jump(ra)
def inputs(p):
 v=symbolic_registers(p)
 for x in REGISTERS:v[f'out_{x}']=claripy.Concat(claripy.BVS(f'{p}_out_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(f'{p}_out_{x}',8)
 v['out_control']=claripy.BVS(f'{p}_out_control',8);v['out_wait']=claripy.BVS(f'{p}_out_wait',8)
 v['control_in']=claripy.BVS(f'{p}_control_in',8);v['wait_in']=claripy.BVS(f'{p}_wait_in',8)
 return v
def setup(s,v):
 s.globals['call']=claripy.BVV(0,10*8)
 for key,val in v.items():
  if key.startswith('out_'):s.globals[key]=val
def assembly(v):
 l=symbol_location(SYMS,'SaffronPidgeyHouse_Script');t=symbol_location(SYMS,'EnableAutoTextBoxDrawing');assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(t.address,Callee())
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v);s.memory.store(W_CONTROL,v['control_in']);s.memory.store(W_DO_NOT_WAIT,v['wait_in']);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=8);assert not m.errored and len(m.found)==1
 return [E(**assembly_registers(x),control=x.memory.load(W_CONTROL,1),wait=x.memory.load(W_DO_NOT_WAIT,1),call=x.globals['call'],constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_saffron_pidgey_house_script');t=p.loader.find_symbol('port_enable_auto_text_box_drawing');assert f and t
 p.hook(t.rebased_addr,NCallee())
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v);s.memory.store(NM+W_CONTROL,v['control_in']);s.memory.store(NM+W_DO_NOT_WAIT,v['wait_in'])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1
 return [E(**native_registers(x,NS),control=x.memory.load(NM+W_CONTROL,1),wait=x.memory.load(NM+W_DO_NOT_WAIT,1),call=x.globals['call'],constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_saffron_pidgey_house_script_pathwise_equivalence():
 v=inputs('saffron_pidgey_house_script');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'control','wait','call'))
