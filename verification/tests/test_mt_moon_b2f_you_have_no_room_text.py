from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;MARKER=0x1234;DONE=0xEFFF;STACK=0xD000;RETURN=0xFFFF
EXPECTED=bytes.fromhex('217f5fcd493cc3d724')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;call:claripy.ast.BV;tse:claripy.ast.BV;marker:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class APrint(angr.SimProcedure):
 """Called PrintText boundary: snapshot inputs, apply the shared arbitrary
 proven transition, then emulate RET back into the caller."""
 def run(self):
  r=assembly_registers(self.state);self.state.globals['call']=claripy.Concat(*(r[x] for x in REGISTERS),self.state.globals['marker'])
  for x in REGISTERS:
   v=self.state.globals[f'out_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  self.state.globals['marker']=self.state.globals['out_marker']
  ra=self.state.memory.load(self.state.regs.sp,2,endness='Iend_LE');self.state.regs.sp=self.state.regs.sp+2;self.jump(ra)
class ATail(angr.SimProcedure):
 """jp TextScriptEnd boundary: record the hand-off registers, apply the
 shared arbitrary proven TextScriptEnd transition, stop."""
 def run(self):
  r=assembly_registers(self.state);self.state.globals['tse']=claripy.Concat(*(r[x] for x in REGISTERS))
  for x in REGISTERS:
   v=self.state.globals[f'e_out_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  self.jump(DONE)
def zret(state):
 ra=state.memory.load(state.regs.sp,8,endness='Iend_LE');state.regs.sp=state.regs.sp+8;return ra
class NPrint(angr.SimProcedure):
 def run(self,s,m):
  self.state.globals['call']=claripy.Concat(self.state.memory.load(s,8),self.state.memory.load(m+MARKER,1));self.state.memory.store(s,claripy.Concat(*(self.state.globals[f'out_{x}'] for x in REGISTERS)));self.state.memory.store(m+MARKER,self.state.globals['out_marker'])
  self.jump(zret(self.state))
class NTail(angr.SimProcedure):
 def run(self,s):
  self.state.globals['tse']=self.state.memory.load(s,8);self.state.memory.store(s,claripy.Concat(*(self.state.globals[f'e_out_{x}'] for x in REGISTERS)))
  self.jump(zret(self.state))
def inputs(p):
 v=symbolic_registers(p);v['marker']=claripy.BVS(p+'_marker',8);v['out_marker']=claripy.BVS(p+'_out_marker',8)
 for pre in ('','e_'):
  for x in REGISTERS:v[f'{pre}out_{x}']=claripy.Concat(claripy.BVS(f'{p}_{pre}out_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(f'{p}_{pre}out_{x}',8)
 return v
def setup(s,v):
 s.globals['marker']=v['marker'];s.globals['out_marker']=v['out_marker'];s.globals['tse']=claripy.BVV(0,64)
 for key,val in v.items():
  if key.startswith(('e_out_','out_')):s.globals[key]=val
def assembly(v):
 l=symbol_location(SYMS,'MtMoonB2FYouHaveNoRoomText');t=symbol_location(SYMS,'PrintText');te=symbol_location(SYMS,'TextScriptEnd');assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
 p.hook(t.address,APrint());p.hook(te.address,ATail())
 s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v);setup(s,v);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=8);assert not m.errored and len(m.found)==1
 return [E(**assembly_registers(x),call=x.globals['call'],tse=x.globals['tse'],marker=x.globals['marker'],constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_mt_moon_b2f_you_have_no_room_text');t=p.loader.find_symbol('port_print_text');te=p.loader.find_symbol('port_text_script_end');assert f and t and te
 p.hook(t.rebased_addr,NPrint());p.hook(te.rebased_addr,NTail())
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v);s.memory.store(NM+MARKER,v['marker'])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1
 return [E(**native_registers(x,NS),call=x.globals['call'],tse=x.globals['tse'],marker=x.memory.load(NM+MARKER,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_mt_moon_b2f_you_have_no_room_text_pathwise_equivalence():
 v=inputs('mt_moon_b2f_you_have_no_room_text');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'call','tse','marker'))
