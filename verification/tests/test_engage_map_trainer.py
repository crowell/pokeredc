from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
from verification.harness.sm83_shims import Sm83LoadAAtHlIncrement, Sm83DecRegister,Sm83LoadAImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x400000;DONE=0xEFFF
W_EXTRA=0xD504;W_INDEX=0xCF13;W_CLASS=0xCD2D;W_SET=0xCD2E
EXPECTED=linked_bytes(ROM,symbol_location(SYMS,'EngageMapTrainer'),23)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;cls:claripy.ast.BV;st:claripy.ast.BV;ptm:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class PTMBoundary(angr.SimProcedure):
 """Proven PlayTrainerMusic boundary at the tail target: snapshot hand-off
 registers and the engaged-class/set RAM bytes, apply the shared arbitrary
 proven transition, stop."""
 def run(self):
  r=assembly_registers(self.state);m=self.state.memory
  self.state.globals['ptm']=claripy.Concat(*(r[x] for x in REGISTERS))
  for x in REGISTERS:
   v=self.state.globals[f'ptm_out_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  self.jump(DONE)
class NPTM(angr.SimProcedure):
 """cpu_register_state* arrives via rdi; explicit RET back into the wrapper."""
 def run(self):
  s=self.state.regs.rdi
  self.state.globals['ptm']=claripy.Concat(*(self.state.memory.load(s+i,1) for i in range(8)))
  self.state.memory.store(s,claripy.Concat(*(self.state.globals[f'ptm_out_{x}'] for x in REGISTERS)))
  ra=self.state.memory.load(self.state.regs.sp,8,endness='Iend_LE');self.state.regs.sp=self.state.regs.sp+8;self.jump(ra)
def inputs(p,index_val):
 v=symbolic_registers(p)
 v['index_in']=claripy.BVV(index_val,8)
 for i in range(6):v[f'extra{i}']=claripy.BVS(f'{p}_extra{i}',8)
 for x in REGISTERS:v[f'ptm_out_{x}']=claripy.Concat(claripy.BVS(f'{p}_ptm_out_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(f'{p}_ptm_out_{x}',8)
 return v
def setup(s,v):
 s.globals['ptm']=claripy.BVV(0,8*8)
 for key,val in v.items():
  if key.startswith('ptm_out_'):s.globals[key]=val
def store_memory(s,v,base=0):
 s.memory.store(base+W_INDEX,v['index_in'])
 for i in range(6):s.memory.store(base+W_EXTRA+i,v[f'extra{i}'])
def assembly(v):
 l=symbol_location(SYMS,'EngageMapTrainer');assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+5,Sm83LoadAImmediate(W_INDEX,b+8),length=3)
 p.hook(b+8,Sm83DecRegister('a',b+9),length=1)
 p.hook(b+12,Sm83LoadAAtHlIncrement(b+13),length=1)
 p.hook(b+13,Sm83StoreAImmediate(W_CLASS,b+16),length=3)
 p.hook(b+17,Sm83StoreAImmediate(W_SET,b+20),length=3)
 p.hook(b+20,PTMBoundary(),length=3)
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v);store_memory(s,v)
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=8);assert not m.errored and len(m.found)==1
 return [E(**assembly_registers(x),cls=x.memory.load(W_CLASS,1),st=x.memory.load(W_SET,1),ptm=x.globals['ptm'],constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_engage_map_trainer');t=p.loader.find_symbol('port_play_trainer_music');assert f and t
 p.hook(t.rebased_addr,NPTM())
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v);store_memory(s,v,NM)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1
 return [E(**native_registers(x,NS),cls=x.memory.load(NM+W_CLASS,1),st=x.memory.load(NM+W_SET,1),ptm=x.globals['ptm'],constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.parametrize('index_val',[1,2,3])
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_engage_map_trainer_pathwise_equivalence(index_val):
 # Three representative 1-based sprite indices exercise all table offsets.
 v=inputs('engage_map_trainer',index_val);assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'cls','st'))
