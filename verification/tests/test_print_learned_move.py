from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;DONE=0xEFFF
STACK=0xD000;RETURN=0xFFFF
EXPECTED=linked_bytes(ROM,symbol_location(SYMS,'PrintLearnedMove'),14)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;pt:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class PTBoundary(angr.SimProcedure):
 def __init__(self,next_address:int)->None:
  super().__init__();self._next=next_address
 def run(self):
  r=assembly_registers(self.state);self.state.globals['pt']=claripy.Concat(*(r[x] for x in REGISTERS))
  for x in REGISTERS:
   v=self.state.globals['pt_out_'+x];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  self.jump(self._next)
class NPT(angr.SimProcedure):
 """cpu_register_state* arrives via rdi; explicit RET."""
 def run(self):
  s=self.state.regs.rdi
  self.state.globals['pt']=self.state.memory.load(s,8)
  self.state.memory.store(s,claripy.Concat(*(self.state.globals[f'pt_out_{x}'] for x in REGISTERS)))
def inputs(p):
 v=symbolic_registers(p)
 for x in REGISTERS:v['pt_out_'+x]=claripy.Concat(claripy.BVS(p+'_pt_out_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(p+'_pt_out_'+x,8)
 return v
def setup(s,v):
 s.globals['pt']=claripy.BVV(0,8*8)
 for key,val in v.items():
  if key.startswith('pt_out_'):s.globals[key]=val
def assembly(v):
 l=symbol_location(SYMS,'PrintLearnedMove');t=symbol_location(SYMS,'PrintText');assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+3,PTBoundary(b+6),length=3)
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(s);m.explore(find=lambda st:st.addr==RETURN,num_find=16);assert not m.errored and len(m.found)==1
 return [E(**assembly_registers(x),pt=x.globals['pt'],constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_print_learned_move');t=p.loader.find_symbol('port_print_text');assert f and t
 p.hook(t.rebased_addr,NPT())
 s=p.factory.call_state(f.rebased_addr,NS);store_native_registers(s,NS,v);setup(s,v)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1
 return [E(**native_registers(x,NS),pt=x.globals['pt'],constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_print_learned_move_pathwise_equivalence():
 v=inputs('print_learned_move');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'pt'))
