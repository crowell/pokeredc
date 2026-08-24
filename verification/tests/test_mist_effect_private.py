from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
from verification.harness.sm83_shims import Sm83AndRegister,Sm83BitAtHl,Sm83LoadAHighImmediate,Sm83SetAtHl
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;STACK=0xd000;RETURN=0xffff;DONE=0xefff;SITES=3;SNAP=8*len(REGISTERS)
PS2=0xd063;ES2=0xd068;TURN=0xfff3
EXPECTED=bytes.fromhex('2163d0f0f3a728032168d0cb4e2010cbce21a87b060fcdd63521527fc3493c21537b060fc3d635')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
 ps2:claripy.ast.BV;es2:claripy.ast.BV;turn:claripy.ast.BV
 ib0:claripy.ast.BV;ib1:claripy.ast.BV;ib2:claripy.ast.BV
 constraints:tuple[claripy.ast.Bool,...]
class ACall(angr.SimProcedure):
 """Proven callee composition boundary at the call/far-tail site: record the
 caller-passed registers, apply this site's arbitrary matching proven
 transition, then continue after the replaced instruction (or terminate for
 the never-returning PrintText / jpfar Bankswitch tails)."""
 def __init__(self,site:int,next_address:int|None)->None:
  super().__init__();self._site=site;self._next=DONE if next_address is None else next_address
 def run(self):
  k=self._site
  r=assembly_registers(self.state);self.state.globals[f'ib{k}']=claripy.Concat(*(r[x] for x in REGISTERS))
  for x in REGISTERS:
   v=self.state.globals[f'out{k}_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
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
 for name,addr in (('ps2',PS2),('es2',ES2),('turn',TURN)):v[name]=claripy.BVS(f'{p}_{name}',8)
 for k in range(SITES):
  for x in REGISTERS:v[f'out{k}_{x}']=claripy.Concat(claripy.BVS(f'{p}_out{k}_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(f'{p}_out{k}_{x}',8)
 return v
def setup(s,v,native:bool):
 for k in range(SITES):s.globals[f'ib{k}']=None
 o=NM if native else 0
 s.memory.store(o+PS2,v['ps2']);s.memory.store(o+ES2,v['es2']);s.memory.store(o+TURN,v['turn'])
 for k in range(SITES):
  for x in REGISTERS:s.globals[f'out{k}_{x}']=v[f'out{k}_{x}']
def assembly(v):
 l=symbol_location(SYMS,'MistEffect_');pt=symbol_location(SYMS,'PrintText')
 assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+3,Sm83LoadAHighImmediate(0xf3,b+5),length=2)      # ldh a,[hWhoseTurn]
 p.hook(b+5,Sm83AndRegister('a',b+6),length=1)              # and a
 p.hook(b+11,Sm83BitAtHl(1,b+13),length=2)                  # bit PROTECTED_BY_MIST,[hl]
 p.hook(b+15,Sm83SetAtHl(1,b+17),length=2)                  # set PROTECTED_BY_MIST,[hl]
 p.hook(b+22,ACall(0,b+25),length=3)                        # call Bankswitch (callfar PlayCurrentMoveAnimation)
 p.hook(pt.address,ACall(1,None))                           # jp PrintText tail
 p.hook(b+36,ACall(2,None),length=3)                        # jp Bankswitch tail (jpfar PrintButItFailedText_)
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v,False);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(s);m.explore(find=lambda st:st.addr==DONE,num_find=64);assert not m.errored and len(m.found)==4
 return [E(**assembly_registers(x),ps2=x.memory.load(PS2,1),es2=x.memory.load(ES2,1),turn=x.memory.load(TURN,1),**{f'ib{k}':(x.globals[f'ib{k}'] if x.globals[f'ib{k}'] is not None else claripy.BVV(0,SNAP)) for k in range(SITES)},constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False)
 syms={n:p.loader.find_symbol(s) for n,s in (('port_play_current_move_animation','port_play_current_move_animation'),('port_print_text','port_print_text'),('port_print_but_it_failed_text_','port_print_but_it_failed_text_'))}
 assert all(syms.values())
 for name,k in (('port_play_current_move_animation',0),('port_print_text',1),('port_print_but_it_failed_text_',2)):p.hook(syms[name].rebased_addr,NCall(k))
 f=p.loader.find_symbol('port_mist_effect_private');assert f
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v,True)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==4
 return [E(**native_registers(x,NS),ps2=x.memory.load(NM+PS2,1),es2=x.memory.load(NM+ES2,1),turn=x.memory.load(NM+TURN,1),**{f'ib{k}':(x.globals[f'ib{k}'] if x.globals[f'ib{k}'] is not None else claripy.BVV(0,SNAP)) for k in range(SITES)},constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_mist_effect_private_pathwise_equivalence():
 v=inputs('mist_effect_private');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'ps2','es2','turn','ib0','ib1','ib2'))
