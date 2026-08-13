from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;NATIVE_CALLBACK=0x100100;NATIVE_GLOBALS=0x100200;STACK=0xd000;RETURN=0xffff
KEYS=('new_sound_id','fade_out_control','audio_rom_bank','saved_audio_rom_bank','dispatched')
class Store(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.jump(self.n)  # type: ignore[override]
class XorA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=claripy.BVV(0,8);self.state.regs.f=claripy.BVV(0x40,8);self.jump(self.n)  # type: ignore[override]
class Boundary(angr.SimProcedure):
 def __init__(self,full):super().__init__();self.full=full
 def run(self):
  self.state.globals['dispatched']=claripy.BVV(1,8)
  if self.full:
   cb=self.state.globals['callback']
   for r in REGISTERS:setattr(self.state.regs,r,sm83_flags_to_z80(cb[r]) if r=='f' else cb[r])
   for k in KEYS[:4]:self.state.globals[k]=cb[k]
  self.jump(RETURN)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 cb=symbolic_registers(f'{p}_callback')
 for r,v in cb.items():i[f'callback_{r}']=v
 for k in KEYS[:4]:i[f'callback_{k}']=claripy.BVS(f'{p}_callback_{k}',8)
 return i
def assembly(i,full):
 l=symbol_location(SYMBOLS,'PlayMusic');sound=symbol_location(SYMBOLS,'PlaySound').address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address
 p.hook(q+1,Store('new_sound_id',q+4),length=3);p.hook(q+4,XorA(q+5),length=1);p.hook(q+5,Store('fade_out_control',q+8),length=3);p.hook(q+9,Store('audio_rom_bank',q+12),length=3);p.hook(q+12,Store('saved_audio_rom_bank',q+15),length=3);p.hook(sound,Boundary(full))
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
 s.globals['callback']={r:i[f'callback_{r}'] for r in REGISTERS}|{k:i[f'callback_{k}'] for k in KEYS[:4]};s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 return [E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[k] for k in KEYS)),constraints=tuple(x.solver.constraints)) for x in collect_returns(p,s,RETURN)]
def native(i,full):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_play_music' if full else 'port_play_music_begin');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE,NATIVE_CALLBACK,NATIVE_GLOBALS) if full else p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)))
 if full:
  store_native_registers(s,NATIVE_CALLBACK,{r:i[f'callback_{r}'] for r in REGISTERS});s.memory.store(NATIVE_GLOBALS,claripy.Concat(*(i[f'callback_{k}'] for k in KEYS[:4])))
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('full',(False,True))
def test_equivalence(full):
 i=inputs(f'play_music_{full}');assert_pathwise_equivalent(assembly(i,full),native(i,full),(*REGISTERS,'memory'))
def test_exact_entry():
 l=symbol_location(SYMBOLS,'PlayMusic');assert linked_bytes(ROM,l,16)==bytes.fromhex('47eaeec0afeac7cf79eaefc0eaf0c078');assert symbol_location(SYMBOLS,'PlaySound').address==0x23b1
