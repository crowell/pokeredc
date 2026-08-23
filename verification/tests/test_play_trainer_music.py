from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate,Sm83CpRegister,Sm83LoadAAtHlIncrement,Sm83LoadAImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x400000;DONE=0xEFFF;STACK=0xD000;RETURN=0xFFFF
W_CLASS=0xCD2D;W_GYM=0xD05C;W_FADE=0xCFC7;W_ROMBANK=0xC0EF;W_SAVEDBANK=0xC0F0;W_NEWSOUND=0xC0EE
EVIL=(0x3439,bytes.fromhex('d5d9dcdde3e4e5e6ff'))
FEMALE=(0x3434,bytes.fromhex('cbcedae8ff'))
EXPECTED=linked_bytes(ROM,symbol_location(SYMS,'PlayTrainerMusic'),76)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;fade:claripy.ast.BV;rbank:claripy.ast.BV;sbank:claripy.ast.BV;newsound:claripy.ast.BV;ps0:claripy.ast.BV;ps1:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class AndACorrect(angr.SimProcedure):
 """SM83 `AND A`: Z per result, H set, N/C clear."""
 def __init__(self,next_address:int)->None:
  super().__init__();self._next=next_address
 def run(self):
  self.state.regs.a=self.state.regs.a & self.state.regs.a
  self.state.regs.f=claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.BVV(0x10,8)
  self.jump(self._next)
class PSBoundary(angr.SimProcedure):
 """Mid-function PlaySound call site (SFX_STOP_ALL_MUSIC): snapshot regs,
 apply invocation 0's shared arbitrary proven transition, continue."""
 def __init__(self,next_address:int)->None:
  super().__init__();self._next=next_address
 def run(self):
  k=self.state.globals['fires'];self.state.globals['fires']=k+1
  r=assembly_registers(self.state);self.state.globals[f'ps{k}']=claripy.Concat(*(r[x] for x in REGISTERS))
  for x in REGISTERS:
   v=self.state.globals[f'ps{k}_out_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  self.jump(self._next)
class TailBoundary(angr.SimProcedure):
 """Tail `jp PlaySound` (song selection): snapshot hand-off registers, apply
 invocation 1's shared arbitrary proven transition, stop."""
 def run(self):
  r=assembly_registers(self.state);self.state.globals['ps1']=claripy.Concat(*(r[x] for x in REGISTERS))
  for x in REGISTERS:
   v=self.state.globals[f'ps1_out_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  self.jump(DONE)
class NPS(angr.SimProcedure):
 """play_sound_state arrives via rdi; explicit RET. Fires once per
 PlaySound invocation (counter distinguishes the two call sites)."""
 def run(self):
  k=self.state.globals['fires'];self.state.globals['fires']=k+1
  s=self.state.regs.rdi;mm=self.state.memory
  self.state.globals[f'ps{k}']=mm.load(s,8)
  mm.store(s,claripy.Concat(*(self.state.globals[f'ps{k}_out_{x}'] for x in REGISTERS)))
  ra=mm.load(self.state.regs.sp,8,endness='Iend_LE');self.state.regs.sp=self.state.regs.sp+8;self.jump(ra)

def inputs(p,class_val,gym_val):
 v=symbolic_registers(p)
 v['class_in']=claripy.BVV(class_val,8)
 v['gym_in']=claripy.BVV(gym_val,8);v['fade_out']=claripy.BVS(f'{p}_fade_out',8)
 v['rombank_in']=claripy.BVS(f'{p}_rombank_in',8);v['sbank_in']=claripy.BVS(f'{p}_sbank_in',8);v['newsound_in']=claripy.BVS(f'{p}_newsound_in',8)
 for k in range(2):
  for x in REGISTERS:v[f'ps{k}_out_{x}']=claripy.Concat(claripy.BVS(f'{p}_ps{k}_out_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(f'{p}_ps{k}_out_{x}',8)
 return v
def setup(s,v):
 s.globals['fires']=0;s.globals['ps0']=claripy.BVV(0,64);s.globals['ps1']=claripy.BVV(0,64)
 for key,val in v.items():
  if key.startswith('ps'):s.globals[key]=val
def store_memory(s,v,base=0):
 s.memory.store(base+W_CLASS,v['class_in']);s.memory.store(base+W_GYM,v['gym_in']);s.memory.store(base+W_FADE,v['fade_out'])
 s.memory.store(base+W_ROMBANK,v['rombank_in']);s.memory.store(base+W_SAVEDBANK,v['sbank_in']);s.memory.store(base+W_NEWSOUND,v['newsound_in'])
def assembly(v):
 l=symbol_location(SYMS,'PlayTrainerMusic');assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 assert linked_bytes(ROM,symbol_location(SYMS,'EvilTrainerList'),9)==EVIL[1]
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+0,Sm83LoadAImmediate(W_CLASS,b+3),length=3)
 p.hook(b+3,Sm83CpImmediate(0xE1,b+5),length=2)
 p.hook(b+6,Sm83CpImmediate(0xF2,b+8),length=2)
 p.hook(b+9,Sm83CpImmediate(0xF3,b+11),length=2)
 p.hook(b+12,Sm83LoadAImmediate(W_GYM,b+14),length=3)
 p.hook(b+15,AndACorrect(b+16),length=1)
 p.hook(b+18,Sm83StoreAImmediate(W_FADE,b+21),length=3)
 p.hook(b+23,PSBoundary(b+26),length=3)
 p.hook(b+28,Sm83StoreAImmediate(W_ROMBANK,b+31),length=3)
 p.hook(b+31,Sm83StoreAImmediate(W_SAVEDBANK,b+34),length=3)
 p.hook(b+34,Sm83LoadAImmediate(W_CLASS,b+37),length=3)
 p.hook(b+41,Sm83LoadAAtHlIncrement(b+42),length=1)
 p.hook(b+42,Sm83CpImmediate(0xFF,b+44),length=2)
 p.hook(b+46,Sm83CpRegister('b',b+47),length=1)
 p.hook(b+56,Sm83LoadAAtHlIncrement(b+57),length=1)
 p.hook(b+57,Sm83CpImmediate(0xFF,b+59),length=2)
 p.hook(b+61,Sm83CpRegister('b',b+62),length=1)
 p.hook(b+70,Sm83StoreAImmediate(W_NEWSOUND,b+73),length=3)
 p.hook(b+73,TailBoundary(),length=3)
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v);store_memory(s,v);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(s);m.explore(find=lambda st:st.addr in (DONE,RETURN),num_find=128);assert not m.errored and m.found
 return [E(**assembly_registers(x),fade=x.memory.load(W_FADE,1),rbank=x.memory.load(W_ROMBANK,1),sbank=x.memory.load(W_SAVEDBANK,1),newsound=x.memory.load(W_NEWSOUND,1),ps0=x.globals['ps0'],ps1=x.globals['ps1'],constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_play_trainer_music');ps=p.loader.find_symbol('port_play_sound');assert f and ps
 p.hook(ps.rebased_addr,NPS())
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v);store_memory(s,v,NM)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and m.deadended
 return [E(**native_registers(x,NS),fade=x.memory.load(NM+W_FADE,1),rbank=x.memory.load(NM+W_ROMBANK,1),sbank=x.memory.load(NM+W_SAVEDBANK,1),newsound=x.memory.load(NM+W_NEWSOUND,1),ps0=x.globals['ps0'],ps1=x.globals['ps1'],constraints=tuple(x.solver.constraints)) for x in m.deadended]
SCENARIOS=[(0xE1,0),(0xF2,0),(0xF3,0),(0xD5,7),(0xCB,0),(0x00,0),(0x50,5)]
@pytest.mark.parametrize('class_val,gym_val',SCENARIOS)
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_play_trainer_music_pathwise_equivalence(class_val,gym_val):
 # Seven concrete (class, gym-leader) scenarios cover every distinct behaviour:
 # three rival early rets, gym-leader early ret, evil/female list hits, and
 # the male default; all other state stays fully symbolic.
 v=inputs('play_trainer_music',class_val,gym_val)
 assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'fade','rbank','sbank','newsound','ps0','ps1'))
