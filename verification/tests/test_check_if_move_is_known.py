from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers,sm83_flags_to_z80
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83CpRegister,Sm83DecRegister,Sm83LoadAAtHlIncrement,Sm83LoadAImmediate,Sm83Scf
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;STACK=0xd000;RETURN=0xffff;SITES=2;WP_K=0
WP=0xcf92;MN=0xd0e0;BASE=0xd173;STRIDE=0x2c;PARTY=6
EXPECTED=bytes.fromhex('fa92cf2173d1012c00cd873afae0d0470e042ab828050d20f9a7c9213b7ecd493c37c9')
MOVES=[('mv%d_%d'%(k,i),BASE+k*STRIDE+i) for k in range(PARTY) for i in range(4)]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
 mv:claripy.ast.BV;wp:claripy.ast.BV;mn:claripy.ast.BV
 ib0:claripy.ast.BV;ib1:claripy.ast.BV
 constraints:tuple[claripy.ast.Bool,...]
class Sm83AndASetH(angr.SimProcedure):
 """SM83 `AND A` (A7): Z from the result, H set, N/C clear."""
 def __init__(self,next_address:int)->None:
  super().__init__();self._next=next_address
 def run(self):
  self.state.regs.f=claripy.If(self.state.regs.a==0,claripy.BVV(0x50,8),claripy.BVV(0x10,8));self.jump(self._next)
def _sum(a,bc,hl0):
 hl0e=claripy.ZeroExt(9,hl0);bce=claripy.ZeroExt(9,bc);ae=claripy.ZeroExt(17,a)
 total=hl0e+ae*bce
 prev=claripy.ZeroExt(16,(hl0e+(ae-1)*bce)[15:0])
 return total[15:0],prev+claripy.ZeroExt(7,bce)
class ACall(angr.SimProcedure):
 """Proven AddNTimes composition boundary at the call site: capture the
 caller-passed registers, then apply the callee's complete deterministic
 transition (A := 0, HL += A*BC, F := Z|N|final-add-carry, or the `and a`
 Z|H when the count is zero)."""
 def __init__(self,next_address:int)->None:
  super().__init__();self._next=next_address
 def run(self):
  r=assembly_registers(self.state);self.state.globals['ib0']=claripy.Concat(*(r[x] for x in REGISTERS))
  hl,carry=_sum(r['a'],claripy.Concat(r['b'],r['c']),claripy.Concat(r['h'],r['l']))
  self.state.regs.a=claripy.BVV(0,8)
  self.state.regs.f=claripy.If(r['a']==0,claripy.BVV(0x50,8),claripy.BVV(0x42,8)|claripy.If(carry>0xffff,claripy.BVV(1,8),claripy.BVV(0,8)))
  self.state.regs.hl=hl
  self.jump(self._next)
class ACall2(angr.SimProcedure):
 """Proven PrintText composition boundary at the callee entry: capture the
 call input, apply this site's arbitrary matching proven transition, then
 return to the caller via the pushed address."""
 def run(self):
  r=assembly_registers(self.state);self.state.globals['ib1']=claripy.Concat(*(r[x] for x in REGISTERS))
  for x in REGISTERS:
   v=self.state.globals[f'out1_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  ret=self.state.memory.load(self.state.regs.sp,2,endness='Iend_LE')
  self.state.regs.sp=self.state.regs.sp+2
  self.jump(ret)
class NCall(angr.SimProcedure):
 """AddNTimes composition boundary at the callee entry: capture the
 callee-visible registers, then apply the complete deterministic
 transition."""
 def run(self,s):
  self.state.globals['ib0']=self.state.memory.load(s,8)
  a=self.state.memory.load(s,1);bc=claripy.Concat(self.state.memory.load(s+2,1),self.state.memory.load(s+3,1));hl0=claripy.Concat(self.state.memory.load(s+6,1),self.state.memory.load(s+7,1))
  hl,carry=_sum(a,bc,hl0)
  f_canon=claripy.If(a==0,claripy.BVV(0xa0,8),claripy.BVV(0xc0,8)|claripy.If(carry>0xffff,claripy.BVV(0x10,8),claripy.BVV(0,8)))
  self.state.memory.store(s,claripy.Concat(claripy.BVV(0,8),f_canon,self.state.memory.load(s+2,4),hl[15:8],hl[7:0]))
class NCall2(angr.SimProcedure):
 def run(self,s,m):
  self.state.globals['ib1']=self.state.memory.load(s,8)
  self.state.memory.store(s,claripy.Concat(*(self.state.globals[f'out1_{x}'] for x in REGISTERS)))
def inputs(p):
 v=symbolic_registers(p)
 for name,addr in MOVES:v[name]=claripy.BVS(f'{p}_{name}',8)
 v['wp']=claripy.BVS(p+'_wp',8);v['mn']=claripy.BVS(p+'_mn',8)
 for k in range(SITES):
  for x in REGISTERS:v[f'out{k}_{x}']=claripy.Concat(claripy.BVS(f'{p}_out{k}_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(f'{p}_out{k}_{x}',8)
 return v
def setup(s,v,native:bool,wp_k:int):
 o=NM if native else 0
 for name,addr in MOVES:s.memory.store(o+addr,v[name])
 s.memory.store(o+WP,v['wp']);s.memory.store(o+MN,v['mn'])
 s.solver.add(v['wp']==wp_k)  # concrete party index: each value proven by its own parameterized run
 for k in range(SITES):
  for x in REGISTERS:s.globals[f'out{k}_{x}']=v[f'out{k}_{x}']
 for k in range(SITES):s.globals[f'ib{k}']=None
def assembly(v):
 l=symbol_location(SYMS,'CheckIfMoveIsKnown');pt=symbol_location(SYMS,'PrintText')
 assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+0,Sm83LoadAImmediate(WP,b+3),length=3)          # ld a,[wWhichPokemon]
 p.hook(b+9,ACall(b+12),length=3)                         # call AddNTimes
 p.hook(b+12,Sm83LoadAImmediate(MN,b+15),length=3)        # ld a,[wMoveNum]
 p.hook(b+18,Sm83LoadAAtHlIncrement(b+19),length=1)       # ld a,[hli]
 p.hook(b+19,Sm83CpRegister('b',b+20),length=1)           # cp b
 p.hook(b+22,Sm83DecRegister('c',b+23),length=1)          # dec c
 p.hook(b+25,Sm83AndASetH(b+26),length=1)                 # and a
 p.hook(b+33,Sm83Scf(b+34),length=1)                      # scf
 p.hook(pt.address,ACall2())                              # call PrintText
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v,False,WP_K);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(s);m.explore(find=lambda st:st.addr==RETURN,num_find=64);assert not m.errored and len(m.found)==5
 return [E(**assembly_registers(x),mv=claripy.Concat(*(x.memory.load(a,1) for _,a in MOVES)),wp=x.memory.load(WP,1),mn=x.memory.load(MN,1),**{f'ib{k}':(x.globals[f'ib{k}'] if x.globals[f'ib{k}'] is not None else claripy.BVV(0,8*len(REGISTERS))) for k in range(SITES)},constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False)
 an=p.loader.find_symbol('port_add_n_times');pt=p.loader.find_symbol('port_print_text');assert an is not None and pt is not None
 p.hook(an.rebased_addr,NCall());p.hook(pt.rebased_addr,NCall2())
 f=p.loader.find_symbol('port_check_if_move_is_known');assert f
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v,True,WP_K)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==5
 return [E(**native_registers(x,NS),mv=claripy.Concat(*(x.memory.load(NM+a,1) for _,a in MOVES)),wp=x.memory.load(NM+WP,1),mn=x.memory.load(NM+MN,1),**{f'ib{k}':(x.globals[f'ib{k}'] if x.globals[f'ib{k}'] is not None else claripy.BVV(0,8*len(REGISTERS))) for k in range(SITES)},constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
@pytest.mark.parametrize('wp_k',range(PARTY))
def test_check_if_move_is_known_pathwise_equivalence(wp_k):
 global WP_K
 WP_K=wp_k
 v=inputs('check_if_move_is_known')
 assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'mv','wp','mn','ib0','ib1'))
