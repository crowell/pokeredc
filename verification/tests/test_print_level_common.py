from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import sm83_flags_to_z80
from verification.harness.rom import linked_bytes,rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x400000;STACK=0xD000;RETURN=0xFFFF
W_TEMP=0xD11E;DONE=0xEFFF;STACK=0xD000;RETURN=0xFFFF
EXPECTED=linked_bytes(ROM,symbol_location(SYMS,'PrintLevelCommon'),14)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;pn:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]

class ZPNBoundary(angr.SimProcedure):
 """Z80-safe boundary: snapshot regs at PrintNumber entry, apply shared transition."""
 def run(self):
  r=assembly_registers(self.state);self.state.globals['pn']=claripy.Concat(*(r[x] for x in REGISTERS))
  for x in REGISTERS:
   v=self.state.globals[f'pn_out_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  self.jump(DONE)

class NPN(angr.SimProcedure):
 """print_number_state* arrives via rdi. Snapshot regs(8)+number[3] as input,
 apply shared pn_out transition on regs."""
 def run(self):
  s=self.state.regs.rdi;mm=self.state.memory
  self.state.globals['pn']=mm.load(s,8)
  mm.store(s,claripy.Concat(*(self.state.globals[f'pn_out_{x}'] for x in REGISTERS)))
def inputs(p):
 v=symbolic_registers(p)
 v['temp_in']=claripy.BVS(p+'_temp_in',8)
 for x in REGISTERS:v[f'pn_out_{x}']=claripy.Concat(claripy.BVS(p+'_pn_out_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(p+'_pn_out_'+x,8)
 return v
def setup(s,v):
 s.globals['pn']=claripy.BVV(0,11*8)
 for key,val in v.items():
  if key.startswith('pn_out_'):s.globals[key]=val
def assembly(v):
 l=symbol_location(SYMS,'PrintLevelCommon');t=symbol_location(SYMS,'PrintNumber');assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(t.address,ZPNBoundary())
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v);s.memory.store(W_TEMP,v['temp_in'])
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=8);assert not m.errored and len(m.found)==1
 return [E(**assembly_registers(x),pn=x.globals['pn'],constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_print_level_common');t=p.loader.find_symbol('port_print_number');assert f and t
 p.hook(t.rebased_addr,NPN())
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v);s.memory.store(NM+W_TEMP,v['temp_in'])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1
 return [E(**native_registers(x,NS),pn=x.globals['pn'],constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_print_level_common_pathwise_equivalence():
 v=inputs('print_level_common');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'pn'))
