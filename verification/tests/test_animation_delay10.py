from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x400000;DONE=0xEFFF
EXPECTED=bytes.fromhex('0e0ac33937')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;df:claripy.ast.BV;vb:claripy.ast.BV;ob:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class DFTail(angr.SimProcedure):
 """Proven DelayFrames boundary at the tail target: snapshot the 10-byte
 delay_frame_state hand-off (registers plus both vblank bytes), apply the
 shared arbitrary proven transition, stop."""
 def run(self):
  r=assembly_registers(self.state);m=self.state.memory
  self.state.globals['df']=claripy.Concat(*(r[x] for x in REGISTERS))
  self.state.globals['vb']=m.load(0xFFD6,1)
  for x in REGISTERS:
   v=self.state.globals[f'df_out_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  self.jump(DONE)
class NDF(angr.SimProcedure):
 def run(self,s):
  mm=self.state.memory
  self.state.globals['df']=mm.load(s,8)
  self.state.globals['vb']=mm.load(s+8,1);self.state.globals['ob']=mm.load(s+9,1)
  mm.store(s,claripy.Concat(*(self.state.globals[f'df_out_{x}'] for x in REGISTERS)))
  mm.store(s+8,self.state.globals['df_out_vb']);mm.store(s+9,self.state.globals['df_out_ob'])
  ra=mm.load(self.state.regs.sp,8,endness='Iend_LE');self.state.regs.sp=self.state.regs.sp+8;self.jump(ra)
def inputs(p):
 v=symbolic_registers(p)
 for x in REGISTERS:v[f'df_out_{x}']=claripy.Concat(claripy.BVS(f'{p}_df_out_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(f'{p}_df_out_{x}',8)
 v['df_out_vb']=claripy.BVS(f'{p}_df_out_vb',8);v['df_out_ob']=claripy.BVS(f'{p}_df_out_ob',8)
 v['vbl_in']=claripy.BVS(f'{p}_vbl_in',8)
 return v
def setup(s,v):
 s.globals['df']=claripy.BVV(0,64);s.globals['vb']=claripy.BVV(0,8);s.globals['ob']=claripy.BVV(0,8)
 for key,val in v.items():
  if key.startswith('df_out_'):s.globals[key]=val
def assembly(v):
 l=symbol_location(SYMS,'AnimationDelay10');t=symbol_location(SYMS,'DelayFrames');assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(t.address,DFTail())
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v);s.memory.store(0xFFD6,v['vbl_in'])
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=8);assert not m.errored and len(m.found)==1
 return [E(**assembly_registers(x),df=x.globals['df'],vb=x.globals['vb'],ob=x.globals['ob'],constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_animation_delay10');t=p.loader.find_symbol('port_delay_frames');assert f and t
 p.hook(t.rebased_addr,NDF())
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v);s.memory.store(NM+0xFFD6,v['vbl_in'])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1
 return [E(**native_registers(x,NS),df=x.globals['df'],vb=x.globals['vb'],ob=x.globals['ob'],constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_animation_delay10_pathwise_equivalence():
 v=inputs('animation_delay10');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'df','vb','ob'))
