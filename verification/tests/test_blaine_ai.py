from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;DONE=0xEFFF;STACK=0xD000;RETURN=0xFFFF
EXPECTED=bytes.fromhex('fe40d0c3{:02x}{:02x}'.format(symbol_location(SYMS,'AIUseSuperPotion').address&0xff,symbol_location(SYMS,'AIUseSuperPotion').address>>8))
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;ai:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class AITail(angr.SimProcedure):
 """Proven AIUseXAttack boundary at the tail target: snapshot hand-off
 registers, apply the shared arbitrary proven transition, stop."""
 def run(self):
  r=assembly_registers(self.state);self.state.globals['ai']=claripy.Concat(*(r[x] for x in REGISTERS))
  for x in REGISTERS:
   v=self.state.globals[f'ai_out_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  self.jump(DONE)
class NAi(angr.SimProcedure):
 def run(self):
  s=self.state.regs.rdi
  self.state.globals['ai']=self.state.memory.load(s,8)
  self.state.memory.store(s,claripy.Concat(*(self.state.globals[f'ai_out_{x}'] for x in REGISTERS)))
  ra=self.state.memory.load(self.state.regs.sp,8,endness='Iend_LE');self.state.regs.sp=self.state.regs.sp+8;self.jump(ra)
def inputs(p):
 v=symbolic_registers(p)
 for x in REGISTERS:v[f'ai_out_{x}']=claripy.Concat(claripy.BVS(f'{p}_ai_out_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(f'{p}_ai_out_{x}',8)
 return v
def setup(s,v):
 s.globals['ai']=claripy.BVV(0,64)
 for key,val in v.items():
  if key.startswith('ai_out_'):s.globals[key]=val
def assembly(v):
 l=symbol_location(SYMS,'BlaineAI');t=symbol_location(SYMS,'AIUseSuperPotion');assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+0,Sm83CpImmediate(0x40,b+2),length=2)
 p.hook(t.address,AITail())
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(s);m.explore(find=lambda st:st.addr in (DONE,RETURN),num_find=8);assert not m.errored and len(m.found)==2
 return [E(**assembly_registers(x),ai=(x.globals['ai'] if x.globals['ai'] is not None else claripy.BVV(0,64)),constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_blaine_ai');t=p.loader.find_symbol('port_ai_use_super_potion');assert f and t
 p.hook(t.rebased_addr,NAi())
 s=p.factory.call_state(f.rebased_addr,NS);store_native_registers(s,NS,v);setup(s,v)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==2
 return [E(**native_registers(x,NS),ai=x.globals['ai'],constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_blaine_ai_pathwise_equivalence():
 v=inputs('blaine_ai');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'ai'))
