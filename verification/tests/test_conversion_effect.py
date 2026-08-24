from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
from verification.harness.sm83_shims import Sm83AndRegister,Sm83BitRegister,Sm83LoadAAtHlIncrement,Sm83LoadAHighImmediate,Sm83LoadAImmediate
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;STACK=0xd000;RETURN=0xffff;DONE=0xefff;SITES=3;SNAP=8*len(REGISTERS)
ET1=0xcfea;ET2=0xcfeb;PT1=0xd019;PT2=0xd01a;ES1=0xd067;PS1=0xd062;TURN=0xfff3
EXPECTED=bytes.fromhex('21eacf1119d0f0f3a7fa67d02807e5626bd1fa62d0cb7720162a12137e1221a87bcdd57921cd79c3493c17e549255021537b060fc3d635')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
 et1:claripy.ast.BV;et2:claripy.ast.BV;pt1:claripy.ast.BV;pt2:claripy.ast.BV;es1:claripy.ast.BV;ps1:claripy.ast.BV;turn:claripy.ast.BV
 ib0:claripy.ast.BV;ib1:claripy.ast.BV;ib2:claripy.ast.BV
 constraints:tuple[claripy.ast.Bool,...]
class ACall(angr.SimProcedure):
 """Proven callee composition boundary at the call/far-tail site: record the
 caller-passed registers, apply this site's arbitrary matching proven
 transition, then continue after the replaced instruction (or terminate for
 the never-returning PrintText / jpfar Bankswitch tails)."""
 def __init__(self,site:int,next_address:int|None,bankswitch_bc:bool=False,thunk_b:int|None=None)->None:
  super().__init__();self._site=site;self._next=DONE if next_address is None else next_address;self._bc=bankswitch_bc;self._tb=thunk_b
 def run(self):
  k=self._site
  if self._tb is not None:self.state.regs.b=claripy.BVV(self._tb,8)  # CallBankF's `ld b,BANK` runs before the callee entry
  r=assembly_registers(self.state);self.state.globals[f'ib{k}']=claripy.Concat(*(r[x] for x in REGISTERS))
  for x in REGISTERS:
   v=self.state.globals[f'out{k}_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  if self._bc:
   # CallBankF returns through Bankswitch's `pop bc` (saved AF frame): B = entry A, C = entry F. The p-code model keeps F in z80 layout, so copy the canonical F byte the real SM83 leaves in C.
   self.state.regs.b=r['a'];self.state.regs.c=r['f']
  self.jump(self._next)
class NCall(angr.SimProcedure):
 def __init__(self,site:int)->None:
  super().__init__();self._site=site
 def run(self,s,m):
  k=self._site
  self.state.globals[f'ib{k}']=claripy.Concat(*(self.state.memory.load(s+i,1) for i in range(len(REGISTERS))))
  self.state.memory.store(s,claripy.Concat(*(self.state.globals[f'out{k}_{x}'] for x in REGISTERS)))
def inputs(p):
 v=symbolic_registers(p)
 for name,addr in (('et1',ET1),('et2',ET2),('pt1',PT1),('pt2',PT2),('es1',ES1),('ps1',PS1),('turn',TURN)):v[name]=claripy.BVS(f'{p}_{name}',8)
 for k in range(SITES):
  for x in REGISTERS:v[f'out{k}_{x}']=claripy.Concat(claripy.BVS(f'{p}_out{k}_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(f'{p}_out{k}_{x}',8)
 return v
def setup(s,v,native:bool):
 for k in range(SITES):s.globals[f'ib{k}']=None
 o=NM if native else 0
 for name,addr in (('et1',ET1),('et2',ET2),('pt1',PT1),('pt2',PT2),('es1',ES1),('ps1',PS1),('turn',TURN)):s.memory.store(o+addr,v[name])
 for k in range(SITES):
  for x in REGISTERS:s.globals[f'out{k}_{x}']=v[f'out{k}_{x}']
def assembly(v):
 l=symbol_location(SYMS,'ConversionEffect_');pt=symbol_location(SYMS,'PrintText')
 assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+6,Sm83LoadAHighImmediate(0xf3,b+8),length=2)       # ldh a,[hWhoseTurn]
 p.hook(b+8,Sm83AndRegister('a',b+9),length=1)               # and a
 p.hook(b+9,Sm83LoadAImmediate(0xd067,b+12),length=3)        # ld a,[wEnemyBattleStatus1]
 p.hook(b+18,Sm83LoadAImmediate(0xd062,b+21),length=3)       # ld a,[wPlayerBattleStatus1]
 p.hook(b+21,Sm83BitRegister(6,'a',b+23),length=2)           # bit INVULNERABLE,a
 p.hook(b+25,Sm83LoadAAtHlIncrement(b+26),length=1)          # ld a,[hli]
 p.hook(b+33,ACall(0,b+36,bankswitch_bc=True,thunk_b=0x0f),length=3)                         # call CallBankF (PlayCurrentMoveAnimation)
 p.hook(pt.address,ACall(1,None))                            # jp PrintText tail
 p.hook(b+52,ACall(2,None),length=3)                         # jp Bankswitch tail (jpfar PrintButItFailedText_)
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v,False);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(s);m.explore(find=lambda st:st.addr==DONE,num_find=64);assert not m.errored and len(m.found)==4
 return [E(**assembly_registers(x),**{n:x.memory.load(a,1) for n,a in (('et1',ET1),('et2',ET2),('pt1',PT1),('pt2',PT2),('es1',ES1),('ps1',PS1),('turn',TURN))},**{f'ib{k}':(x.globals[f'ib{k}'] if x.globals[f'ib{k}'] is not None else claripy.BVV(0,SNAP)) for k in range(SITES)},constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False)
 syms={n:p.loader.find_symbol(s) for n,s in (('port_play_current_move_animation','port_play_current_move_animation'),('port_print_text','port_print_text'),('port_print_but_it_failed_text_','port_print_but_it_failed_text_'))}
 assert all(syms.values())
 for name,k in (('port_play_current_move_animation',0),('port_print_text',1),('port_print_but_it_failed_text_',2)):p.hook(syms[name].rebased_addr,NCall(k))
 f=p.loader.find_symbol('port_conversion_effect');assert f
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v,True)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==4
 return [E(**native_registers(x,NS),**{n:x.memory.load(NM+a,1) for n,a in (('et1',ET1),('et2',ET2),('pt1',PT1),('pt2',PT2),('es1',ES1),('ps1',PS1),('turn',TURN))},**{f'ib{k}':(x.globals[f'ib{k}'] if x.globals[f'ib{k}'] is not None else claripy.BVV(0,SNAP)) for k in range(SITES)},constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_conversion_effect_pathwise_equivalence():
 v=inputs('conversion_effect');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'et1','et2','pt1','pt2','es1','ps1','turn','ib0','ib1','ib2'))
