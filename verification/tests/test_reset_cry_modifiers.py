from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
from verification.harness.sm83_shims import Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x400000;DONE=0xEFFF
W_FREQ=0xC0F1;W_TEMPO=0xC0F2
EXPECTED=linked_bytes(ROM,symbol_location(SYMS,'ResetCryModifiers'),11)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;freq:claripy.ast.BV;tempo:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class TailBoundary(angr.SimProcedure):
 """Proven PlaySound boundary at the tail target: snapshot hand-off state,
 apply the shared arbitrary proven transition, stop."""
 def run(self):
  r=assembly_registers(self.state);self.state.globals['ps']=claripy.Concat(*(r[x] for x in REGISTERS))
  for x in REGISTERS:
   v=self.state.globals[f'ps_out_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  self.jump(DONE)
class NPS(angr.SimProcedure):
 def run(self):
  s=self.state.regs.rdi;mm=self.state.memory
  self.state.globals['ps']=claripy.Concat(mm.load(s,8),mm.load(s+8,1))
  mm.store(s,claripy.Concat(*(self.state.globals[f'ps_out_{x}'] for x in REGISTERS)))
  ra=mm.load(self.state.regs.sp,8,endness='Iend_LE');self.state.regs.sp=self.state.regs.sp+8;self.jump(ra)

def inputs(p):
 v=symbolic_registers(p)
 v['freq_in']=claripy.BVS(f'{p}_freq_in',8);v['tempo_in']=claripy.BVS(f'{p}_tempo_in',8)
 for x in REGISTERS:v[f'ps_out_{x}']=claripy.Concat(claripy.BVS(f'{p}_ps_out_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(f'{p}_ps_out_{x}',8)
 return v
def setup(s,v):
 s.globals['ps']=claripy.BVV(0,8*8)
 for key,val in v.items():
  if key.startswith('ps_out_'):s.globals[key]=val
def store_memory(s,v,base=0):
 s.memory.store(base+W_FREQ,v['freq_in']);s.memory.store(base+W_TEMPO,v['tempo_in'])
def assembly(v):
 l=symbol_location(SYMS,'ResetCryModifiers');assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+1,Sm83StoreAImmediate(W_FREQ,b+4),length=3)
 p.hook(b+4,Sm83StoreAImmediate(W_TEMPO,b+7),length=3)
 p.hook(b+7,TailBoundary(),length=3)
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v);store_memory(s,v)
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=8);assert not m.errored and len(m.found)==1
 return [E(**assembly_registers(x),freq=x.memory.load(W_FREQ,1),tempo=x.memory.load(W_TEMPO,1),constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_reset_cry_modifiers');t=p.loader.find_symbol('port_play_sound');assert f and t
 p.hook(t.rebased_addr,NPS())
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v);store_memory(s,v,NM)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1
 return [E(**native_registers(x,NS),freq=x.memory.load(NM+W_FREQ,1),tempo=x.memory.load(NM+W_TEMPO,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_reset_cry_modifiers_pathwise_equivalence():
 v=inputs('reset_cry_modifiers');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'freq','tempo'))
