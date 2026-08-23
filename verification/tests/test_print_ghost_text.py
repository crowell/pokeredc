from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;MARKER=0x1234
EXPECTED=bytes.fromhex('cd3a58c0f0f3a7200efa18d0e627c0213058cd493cafc9213558cd493cafc9')
STATE=('is_in_battle','whose_turn','battle_mon_status')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;state:claripy.ast.BV;calls:claripy.ast.BV;marker:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 v=symbolic_registers(p)
 for k in STATE:v[k]=claripy.BVS(f'{p}_{k}',8)
 v['marker']=claripy.BVS(p+'_marker',8);v['print_marker']=claripy.BVS(p+'_print_marker',8)
 for n in ('ghost','print'):
  for r in REGISTERS:v[f'{n}_{r}']=claripy.Concat(claripy.BVS(f'{p}_{n}_flags',4),claripy.BVV(0,4)) if r=='f' else claripy.BVS(f'{p}_{n}_{r}',8)
 return v
def setregs(s,v,n):
 for r in REGISTERS:
  x=v[f'{n}_{r}'];setattr(s.regs,r,sm83_flags_to_z80(x) if r=='f' else x)
def regs(s):
 x=assembly_registers(s);return [x[r] for r in REGISTERS]
def finish(s,v,gcall,pcall,marker):return E(**assembly_registers(s),state=claripy.Concat(*(v[k] for k in STATE)),calls=claripy.Concat(gcall,pcall),marker=marker,constraints=tuple(s.solver.constraints))
def print_path(s,v,gcall,pointer):
 s.regs.h=claripy.BVV(pointer>>8,8);s.regs.l=claripy.BVV(pointer&255,8);pcall=claripy.Concat(*regs(s),v['marker']);setregs(s,v,'print');s.regs.a=claripy.BVV(0,8);s.regs.f=claripy.BVV(0x40,8);return finish(s,v,gcall,pcall,v['print_marker'])
class Ghost(angr.SimProcedure):
 def run(self,p):self.state.globals['gc']=self.state.memory.load(p,9);self.state.memory.store(p,claripy.Concat(*(self.state.globals[f'ghost_{r}'] for r in REGISTERS)))
class Print(angr.SimProcedure):
 def run(self,p,m):self.state.globals['pc']=claripy.Concat(self.state.memory.load(p,8),self.state.memory.load(m+MARKER,1));self.state.memory.store(p,claripy.Concat(*(self.state.globals[f'print_{r}'] for r in REGISTERS)));self.state.memory.store(m+MARKER,self.state.globals['print_marker'])
def assembly(v):
 l=symbol_location(SYMS,'PrintGhostText');assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v);gcall=claripy.Concat(*regs(s),v['is_in_battle']);setregs(s,v,'ghost');zero=claripy.BVV(0,72);z=(v['ghost_f']&0x80)!=0;ends=[]
 no=s.copy();no.add_constraints(~z);ends.append(finish(no,v,gcall,zero,v['marker']))
 base=s.copy();base.add_constraints(z);base.regs.a=v['whose_turn'];base.regs.f=claripy.If(v['whose_turn']==0,claripy.BVV(0x50,8),claripy.BVV(0x10,8))
 gt=base.copy();gt.add_constraints(v['whose_turn']!=0);ends.append(print_path(gt,v,gcall,0x5835))
 player=base.copy();player.add_constraints(v['whose_turn']==0);masked=v['battle_mon_status']&0x47;player.regs.a=masked;player.regs.f=claripy.If(masked==0,claripy.BVV(0x50,8),claripy.BVV(0x10,8));blocked=player.copy();blocked.add_constraints(masked!=0);ends.append(finish(blocked,v,gcall,zero,v['marker']));scared=player.copy();scared.add_constraints(masked==0);ends.append(print_path(scared,v,gcall,0x5830));return ends
def setup(s,v):
 store_native_registers(s,NS,v)
 for i,k in enumerate(STATE,8):s.memory.store(NS+i,v[k])
 s.memory.store(NM+MARKER,v['marker']);s.globals['print_marker']=v['print_marker'];s.globals['pc']=claripy.BVV(0,72)
 for n in ('ghost','print'):
  for r in REGISTERS:s.globals[f'{n}_{r}']=v[f'{n}_{r}']
def native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_print_ghost_text');g=p.loader.find_symbol('port_is_ghost_battle');t=p.loader.find_symbol('port_print_text');assert f and g and t;p.hook(g.rebased_addr,Ghost());p.hook(t.rebased_addr,Print());s=p.factory.call_state(f.rebased_addr,NS,NM);setup(s,v);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NS),state=x.memory.load(NS+8,3),calls=claripy.Concat(x.globals['gc'],x.globals['pc']),marker=x.memory.load(NM+MARKER,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_print_ghost_text_pathwise_equivalence():
 v=inputs('print_ghost_text');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'state','calls','marker'))
