from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x400000;DONE=0xEFFF;STACK=0xD000;RETURN=0xFFFF
H_VBLANK=0xFFD6
EXPECTED=linked_bytes(ROM,symbol_location(SYMS,'HoFPrintTextAndDelay'),9)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;vbl:claripy.ast.BV;pt:claripy.ast.BV;df:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class PrintBoundary(angr.SimProcedure):
 """Proven PrintText composition at the called entry: snapshot registers,
 apply the shared arbitrary proven transition, continue after the replaced CALL."""
 def __init__(self,next_address:int)->None:
  super().__init__();self._next=next_address
 def run(self):
  r=assembly_registers(self.state);self.state.globals['pt']=claripy.Concat(*(r[x] for x in REGISTERS))
  for x in REGISTERS:
   v=self.state.globals[f'pt_out_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  self.jump(self._next)
class DFBoundary(angr.SimProcedure):
 """Proven DelayFrames boundary at the tail target: snapshot the hand-off
 state (registers plus hVBlankOccurred), apply the shared arbitrary proven
 transition, stop."""
 def run(self):
  r=assembly_registers(self.state);m=self.state.memory
  self.state.globals['df']=claripy.Concat(*(r[x] for x in REGISTERS),m.load(H_VBLANK,1))
  for x in REGISTERS:
   v=self.state.globals[f'df_out_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  m.store(H_VBLANK,self.state.globals['df_out_vb'])
  self.jump(DONE)
class NPT(angr.SimProcedure):
 """cpu_register_state* arrives via rdi; explicit RET."""
 def run(self):
  s=self.state.regs.rdi
  self.state.globals['pt']=self.state.memory.load(s,8)
  self.state.memory.store(s,claripy.Concat(*(self.state.globals[f'pt_out_{x}'] for x in REGISTERS)))
  ra=self.state.memory.load(self.state.regs.sp,8,endness='Iend_LE');self.state.regs.sp=self.state.regs.sp+8;self.jump(ra)
class NDF(angr.SimProcedure):
 """delay_frame_state* arrives via rdi; explicit RET. Snapshot = registers
 (8 bytes) followed by vblank_occurred (+8)."""
 def run(self):
  s=self.state.regs.rdi;mm=self.state.memory
  self.state.globals['df']=claripy.Concat(mm.load(s,8),mm.load(s+8,1))
  mm.store(s,claripy.Concat(*(self.state.globals[f'df_out_{x}'] for x in REGISTERS)))
  mm.store(s+8,self.state.globals['df_out_vb'])
  ra=mm.load(self.state.regs.sp,8,endness='Iend_LE');self.state.regs.sp=self.state.regs.sp+8;self.jump(ra)
def inputs(p):
 v=symbolic_registers(p)
 for pre in ('pt','df'):
  for x in REGISTERS:v[f'{pre}_out_{x}']=claripy.Concat(claripy.BVS(f'{p}_{pre}_out_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(f'{p}_{pre}_out_{x}',8)
 v['df_out_vb']=claripy.BVS(f'{p}_df_out_vb',8)
 v['vbl_in']=claripy.BVS(f'{p}_vbl_in',8)
 return v
def setup(s,v):
 s.globals['pt']=claripy.BVV(0,8*8);s.globals['df']=claripy.BVV(0,9*8)
 for key,val in v.items():
  if key.startswith(('pt_out_','df_out_')):s.globals[key]=val
def store_memory(s,v,base=0):
 s.memory.store(base+H_VBLANK,v['vbl_in'])
def assembly(v):
 l=symbol_location(SYMS,'HoFPrintTextAndDelay');assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+0,PrintBoundary(b+3),length=3)
 p.hook(d.address if False else symbol_location(SYMS,'DelayFrames').address,DFBoundary(),length=3)
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v);store_memory(s,v);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(s);m.explore(find=lambda st:st.addr in (DONE,RETURN),num_find=16);assert not m.errored and len(m.found)==1
 return [E(**assembly_registers(x),vbl=x.memory.load(H_VBLANK,1),pt=x.globals['pt'],df=x.globals['df'],constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_hof_print_text_and_delay');pt=p.loader.find_symbol('port_print_text');df=p.loader.find_symbol('port_delay_frames');assert f and pt and df
 p.hook(pt.rebased_addr,NPT());p.hook(df.rebased_addr,NDF())
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v);store_memory(s,v,NM)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1
 return [E(**native_registers(x,NS),vbl=x.memory.load(NM+H_VBLANK,1),pt=x.globals['pt'],df=x.globals['df'],constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_hof_print_text_and_delay_pathwise_equivalence():
 v=inputs('hof_print_text_and_delay');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'vbl','pt','df'))
