from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000
EXPECTED=bytes.fromhex('0e00cda56d0c79fe0420f7c9')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;selectors:claripy.ast.BV;calls:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 v=symbolic_registers(p);v['whose']=claripy.BVS(p+'_whose',8);v['index']=claripy.BVS(p+'_index',8)
 for i in range(4):
  for r in REGISTERS:v[f'o{i}_{r}']=claripy.Concat(claripy.BVS(f'{p}_o{i}_flags',4),claripy.BVV(0,4)) if r=='f' else claripy.BVS(f'{p}_o{i}_{r}',8)
 return v
def setout(s,v,i):
 for r in REGISTERS:
  x=v[f'o{i}_{r}'];setattr(s.regs,r,sm83_flags_to_z80(x) if r=='f' else x)
class Summary(angr.SimProcedure):
 def run(self,p):
  i=self.state.globals['i'];self.state.globals[f'call{i}']=self.state.memory.load(p,10);self.state.memory.store(p,claripy.Concat(*(self.state.globals[f'o{i}_{r}'] for r in REGISTERS)));self.state.globals['i']=i+1
def assembly(v):
 l=symbol_location(SYMS,'CalculateModifiedStats');assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v);s.regs.c=claripy.BVV(0,8);calls=[]
 for i in range(4):
  before_b,before_c=s.regs.b,s.regs.c;calls.append(claripy.Concat(*[assembly_registers(s)[r] for r in REGISTERS],v['whose'],before_c));setout(s,v,i);s.regs.b=before_b;s.regs.c=before_c;before=s.regs.c;res=before+1;f=s.regs.f&1;f|=claripy.If(res==0,claripy.BVV(0x40,8),claripy.BVV(0,8));f|=claripy.If((before&15)==15,claripy.BVV(0x10,8),claripy.BVV(0,8));s.regs.c=res;s.regs.a=res;cmp=res-4;f=claripy.BVV(2,8)|claripy.If(cmp==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If((res&15)<4,claripy.BVV(0x10,8),claripy.BVV(0,8))|claripy.If(res<4,claripy.BVV(1,8),claripy.BVV(0,8));s.regs.f=f
 return [E(**assembly_registers(s),selectors=claripy.Concat(v['whose'],v['index']),calls=claripy.Concat(*calls),constraints=tuple(s.solver.constraints))]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_calculate_modified_stats');c=p.loader.find_symbol('port_calculate_modified_stat');assert f and c;p.hook(c.rebased_addr,Summary());s=p.factory.call_state(f.rebased_addr,NS);store_native_registers(s,NS,v);s.memory.store(NS+8,v['whose']);s.memory.store(NS+9,v['index']);s.globals['i']=0
 for i in range(4):
  for r in REGISTERS:s.globals[f'o{i}_{r}']=v[f'o{i}_{r}']
 m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NS),selectors=x.memory.load(NS+8,2),calls=claripy.Concat(*(x.globals[f'call{i}'] for i in range(4))),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_calculate_modified_stats_pathwise_equivalence():
 v=inputs('calculate_modified_stats');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'selectors','calls'))
