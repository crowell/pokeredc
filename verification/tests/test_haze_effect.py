from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83AndRegister,Sm83DecRegister,Sm83LoadAAtHlIncrement,Sm83LoadAFromImmediate,Sm83LoadAHighImmediate,Sm83ResAtHl,Sm83StoreAAtHlIncrement,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;STACK=0xd000;RETURN=0xffff;DONE=0xefff;SITES=2
EXPECTED=bytes.fromhex('3e07211acdcd437a212ecdcd437a2112cd1125d0cd4a7a2126cd11f6cfcd4a7a21e9cf11ddccf0f3a728042118d01b7e3600e62728033eff12afea6dd0ea72d021eecc22772162d0cd377a2167d0cd377a21a87bcdd57921537ac3493c')
PM=0xcd1a;EM=0xcd2e;PU=0xcd12;EU=0xcd26;PB=0xd025;EB=0xcff6;STE=0xcfe9;STB=0xd018;SME=0xccdd;SMP=0xccdc;DMP=0xd06d;DME=0xd072;DMN=0xccee;PS=0xd062;ES=0xd067
TURN=0xfff3
MEM=(('pm',PM,8),('em',EM,8),('pu',PU,8),('eu',EU,8),('pb',PB,8),('eb',EB,8),('ste',STE,1),('stb',STB,1),('sme',SME,1),('smp',SMP,1),('dmp',DMP,1),('dme',DME,1),('dmn',DMN,2),('ps',PS,3),('es',ES,3),('turn',TURN,1))
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
 pm:claripy.ast.BV;em:claripy.ast.BV;pu:claripy.ast.BV;eu:claripy.ast.BV;pb:claripy.ast.BV;eb:claripy.ast.BV
 ste:claripy.ast.BV;stb:claripy.ast.BV;sme:claripy.ast.BV;smp:claripy.ast.BV;dmp:claripy.ast.BV;dme:claripy.ast.BV;dmn:claripy.ast.BV;ps:claripy.ast.BV;es:claripy.ast.BV;turn:claripy.ast.BV
 ib0:claripy.ast.BV;ib1:claripy.ast.BV
 constraints:tuple[claripy.ast.Bool,...]
class Sm83AndByteSetH(angr.SimProcedure):
 """SM83 `AND n`: Z from result, H set, N/C clear. The shared AndImmediate
 shim clears H, which is wrong for live flags."""
 def __init__(self,immediate:int,next_address:int)->None:
  super().__init__();self._imm=immediate;self._next=next_address
 def run(self):
  self.state.regs.a=self.state.regs.a&self._imm
  self.state.regs.f=claripy.If(self.state.regs.a==0,claripy.BVV(0x50,8),claripy.BVV(0x10,8))
  self.jump(self._next)
class ACall(angr.SimProcedure):
 """Proven callee composition boundary. The CallBankF site models the thunk's
 `ld b,$0f` before capture and Bankswitch's saved-AF `pop bc` after the
 arbitrary PlayCurrentMoveAnimation transition; the PrintText tail applies
 its arbitrary transition and terminates."""
 def __init__(self,site:int,next_address:int|None,thunk_b:int|None=None,bankswitch_bc:bool=False)->None:
  super().__init__();self._site=site;self._next=DONE if next_address is None else next_address;self._tb=thunk_b;self._bc=bankswitch_bc
 def run(self):
  k=self._site
  if self._tb is not None:self.state.regs.b=claripy.BVV(self._tb,8)
  r=assembly_registers(self.state);self.state.globals[f'ib{k}']=claripy.Concat(*(r[x] for x in REGISTERS))
  for x in REGISTERS:
   v=self.state.globals[f'out{k}_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  if self._bc:
   self.state.regs.b=r['a'];self.state.regs.c=r['f']
  self.jump(self._next)
class NCall(angr.SimProcedure):
 def __init__(self,site:int)->None:
  super().__init__();self._site=site
 def run(self,s,m):
  k=self._site
  self.state.globals[f'ib{k}']=self.state.memory.load(s,8)
  self.state.memory.store(s,claripy.Concat(*(self.state.globals[f'out{k}_{x}'] for x in REGISTERS)))
def inputs(p):
 v=symbolic_registers(p)
 for name,addr,w in MEM:v[name]=claripy.BVS(f'{p}_{name}',8*w)
 for k in range(SITES):
  for x in REGISTERS:v[f'out{k}_{x}']=claripy.Concat(claripy.BVS(f'{p}_out{k}_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(f'{p}_out{k}_{x}',8)
 return v
def setup(s,v,native:bool):
 o=NM if native else 0
 for name,addr,w in MEM:s.memory.store(o+addr,v[name])
 for k in range(SITES):
  for x in REGISTERS:s.globals[f'out{k}_{x}']=v[f'out{k}_{x}']
def assembly(v):
 l=symbol_location(SYMS,'HazeEffect_');cv=symbol_location(SYMS,'CureVolatileStatuses');rm=symbol_location(SYMS,'ResetStatMods');rs=symbol_location(SYMS,'ResetStats');pt=symbol_location(SYMS,'PrintText')
 assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+0,Sm83LoadAFromImmediate(b+1,b+2),length=2)        # ld a,$7
 p.hook(b+38,Sm83LoadAHighImmediate(0xf3,b+40),length=2)     # ldh a,[hWhoseTurn]
 p.hook(b+40,Sm83AndRegister('a',b+41),length=1)             # and a
 p.hook(b+50,Sm83AndImmediate(0x27,b+52),length=2)           # and SLP|FRZ
 p.hook(b+58,Sm83StoreAImmediate(0xd06d,b+61),length=3)      # ld [wPlayerDisabledMove],a
 p.hook(b+61,Sm83StoreAImmediate(0xd072,b+64),length=3)      # ld [wEnemyDisabledMove],a
 p.hook(b+67,Sm83StoreAAtHlIncrement(b+68),length=1)         # ld [hli],a (wPlayerDisabledMoveNumber)
 p.hook(cv.address+0,Sm83ResAtHl(7,cv.address+2),length=2)   # res CONFUSED,[hl]
 p.hook(cv.address+4,Sm83AndByteSetH(0x78,cv.address+6),length=2)  # and $78
 p.hook(cv.address+6,Sm83StoreAAtHlIncrement(cv.address+7),length=1)  # ld [hli],a
 p.hook(cv.address+8,Sm83AndByteSetH(0xf8,cv.address+10),length=2) # and $f8
 p.hook(rm.address+2,Sm83StoreAAtHlIncrement(rm.address+3),length=1)  # ld [hli],a
 p.hook(rm.address+3,Sm83DecRegister('b',rm.address+4),length=1)      # dec b
 p.hook(rs.address+2,Sm83LoadAAtHlIncrement(rs.address+3),length=1)   # ld a,[hli]
 p.hook(rs.address+5,Sm83DecRegister('b',rs.address+6),length=1)      # dec b
 p.hook(b+84,ACall(0,b+87,thunk_b=0x0f,bankswitch_bc=True),length=3)  # call CallBankF
 p.hook(pt.address,ACall(1,None))                                     # jp PrintText tail
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v,False);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(s);m.explore(find=lambda st:st.addr==DONE,num_find=64);assert not m.errored and len(m.found)==4
 return [E(**assembly_registers(x),**{n:x.memory.load(a,w) for n,a,w in MEM},**{f'ib{k}':x.globals[f'ib{k}'] for k in range(SITES)},constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False)
 syms={n:p.loader.find_symbol(s) for n,s in (('port_play_current_move_animation','port_play_current_move_animation'),('port_print_text','port_print_text'))}
 assert all(syms.values())
 for name,k in (('port_play_current_move_animation',0),('port_print_text',1)):p.hook(syms[name].rebased_addr,NCall(k))
 f=p.loader.find_symbol('port_haze_effect');assert f
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v,True)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==4
 return [E(**native_registers(x,NS),**{n:x.memory.load(NM+a,w) for n,a,w in MEM},**{f'ib{k}':x.globals[f'ib{k}'] for k in range(SITES)},constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_haze_effect_pathwise_equivalence():
 v=inputs('haze_effect');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,*(n for n,_,_ in MEM),'ib0','ib1'))
