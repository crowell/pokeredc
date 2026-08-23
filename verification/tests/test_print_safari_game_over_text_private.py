from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;JOY=0xcd6b;MARKER=0x1234;DONE=0xefff;EXPECTED=bytes.fromhex('afea6bcd21f769c3493c')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;call:claripy.ast.BV;joy:claripy.ast.BV;marker:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Prefix(angr.SimProcedure):
 def run(self):self.state.regs.a=claripy.BVV(0,8);self.state.regs.f=claripy.BVV(0x40,8);self.state.memory.store(JOY,claripy.BVV(0,8));self.state.regs.h=claripy.BVV(0x69,8);self.state.regs.l=claripy.BVV(0xf7,8);self.jump(self.addr+7)
class ACall(angr.SimProcedure):
 def run(self):
  r=assembly_registers(self.state);self.state.globals['call']=claripy.Concat(*(r[x] for x in REGISTERS),self.state.memory.load(JOY,1),self.state.globals['marker'])
  for x in REGISTERS:
   v=self.state.globals[f'out_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  self.state.memory.store(JOY,self.state.globals['out_joy']);self.state.globals['marker']=self.state.globals['out_marker'];self.jump(DONE)
class NCall(angr.SimProcedure):
 def run(self,s,m):self.state.globals['call']=claripy.Concat(self.state.memory.load(s,8),self.state.memory.load(m+JOY,1),self.state.memory.load(m+MARKER,1));self.state.memory.store(s,claripy.Concat(*(self.state.globals[f'out_{x}'] for x in REGISTERS)));self.state.memory.store(m+JOY,self.state.globals['out_joy']);self.state.memory.store(m+MARKER,self.state.globals['out_marker'])
def inputs(p):
 v=symbolic_registers(p)
 for k in ('joy','marker','out_joy','out_marker'):v[k]=claripy.BVS(f'{p}_{k}',8)
 for x in REGISTERS:v[f'out_{x}']=claripy.Concat(claripy.BVS(p+'_out_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(f'{p}_out_{x}',8)
 return v
def setup(s,v):
 for k in ('marker','out_joy','out_marker'):s.globals[k]=v[k]
 for x in REGISTERS:s.globals[f'out_{x}']=v[f'out_{x}']
def assembly(v):
 l=symbol_location(SYMS,'PrintSafariGameOverText');t=symbol_location(SYMS,'PrintText');assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});p.hook(l.address,Prefix(),length=7);p.hook(t.address,ACall());s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v);s.memory.store(JOY,v['joy']);setup(s,v);m=p.factory.simulation_manager(s);m.explore(find=DONE);assert not m.errored;return [E(**assembly_registers(x),call=x.globals['call'],joy=x.memory.load(JOY,1),marker=x.globals['marker'],constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_print_safari_game_over_text_private');t=p.loader.find_symbol('port_print_text');assert f and t;p.hook(t.rebased_addr,NCall());s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);s.memory.store(NM+JOY,v['joy']);s.memory.store(NM+MARKER,v['marker']);setup(s,v);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NS),call=x.globals['call'],joy=x.memory.load(NM+JOY,1),marker=x.memory.load(NM+MARKER,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_print_safari_game_over_text_private_pathwise_equivalence():
 v=inputs('print_safari_game_over');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'call','joy','marker'))
