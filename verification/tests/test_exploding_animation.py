from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83BitRegister,Sm83CpImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;NATIVE_CALLBACK=0x100100;NATIVE_GLOBALS=0x100200;STACK=0xd000;RETURN=0xffff;DONE=0xefff
KEYS=('whose_turn','player_move','enemy_move','enemy_type1','enemy_type2','player_type1','player_type2','enemy_status1','move_missed','animation_type','dispatched')
class Read(angr.SimProcedure):
 def __init__(self,key,n,hli=False):super().__init__();self.key=key;self.n=n;self.hli=hli
 def run(self):self.state.regs.a=self.state.globals[self.key];self.state.regs.hl=self.state.regs.hl+(1 if self.hli else 0);self.jump(self.n)  # type: ignore[override]
class ReadSelectedType(angr.SimProcedure):
 def __init__(self,second,n):super().__init__();self.second=second;self.n=n
 def run(self):
  key=claripy.If(self.state.globals['whose_turn']==0,self.state.globals['enemy_type2' if self.second else 'enemy_type1'],self.state.globals['player_type2' if self.second else 'player_type1']);self.state.regs.a=key;self.state.regs.hl=self.state.regs.hl+(0 if self.second else 1);self.jump(self.n)  # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.jump(self.n)  # type: ignore[override]
class Boundary(angr.SimProcedure):
 def __init__(self,full):super().__init__();self.full=full
 def run(self):
  self.state.globals['dispatched']=claripy.BVV(1,8)
  if self.full:
   cb=self.state.globals['callback']
   for r in REGISTERS:setattr(self.state.regs,r,sm83_flags_to_z80(cb[r]) if r=='f' else cb[r])
   for k in KEYS[:10]:self.state.globals[k]=cb[k]
  self.jump(DONE)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 for r,v in symbolic_registers(p+'_callback').items():i['callback_'+r]=v
 for k in KEYS[:10]:i['callback_'+k]=claripy.BVS(f'{p}_callback_{k}',8)
 return i
def assembly(i,full):
 l=symbol_location(SYMBOLS,'HandleExplodingAnimation');target=symbol_location(SYMBOLS,'PlayMoveAnimation').address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q,Read('whose_turn',q+2),length=2);p.hook(q+2,Sm83AndImmediate(0xff,q+3),length=1);p.hook(q+9,Read('player_move',q+12),length=3);p.hook(q+20,Read('enemy_move',q+23),length=3);p.hook(q+23,Sm83CpImmediate(0x78,q+25),length=2);p.hook(q+27,Sm83CpImmediate(0x99,q+29),length=2);p.hook(q+30,Read('enemy_status1',q+31),length=1);p.hook(q+31,Sm83BitRegister(6,'a',q+33),length=2);p.hook(q+34,ReadSelectedType(False,q+35),length=1);p.hook(q+35,Sm83CpImmediate(8,q+37),length=2);p.hook(q+38,ReadSelectedType(True,q+39),length=1);p.hook(q+39,Sm83CpImmediate(8,q+41),length=2);p.hook(q+42,Read('move_missed',q+45),length=3);p.hook(q+45,Sm83AndImmediate(0xff,q+46),length=1);p.hook(q+49,Store('animation_type',q+52),length=3);p.hook(target,Boundary(full));s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
 s.globals['dispatched']=claripy.BVV(0,8);s.globals['callback']={r:i['callback_'+r] for r in REGISTERS}|{k:i['callback_'+k] for k in KEYS[:10]};s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');m=p.factory.simulation_manager(s);m.stashes['terminal']=[]
 while m.active:
  m.move(from_stash='active',to_stash='terminal',filter_func=lambda x:x.addr in (RETURN,DONE))
  if m.active:m.step()
 assert not m.errored;return [E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[k] for k in KEYS)),constraints=tuple(x.solver.constraints)) for x in m.terminal]
def native(i,full):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);name='port_handle_exploding_animation' if full else 'port_handle_exploding_animation_begin';fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE,NATIVE_CALLBACK,NATIVE_GLOBALS) if full else p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)))
 if full:store_native_registers(s,NATIVE_CALLBACK,{r:i['callback_'+r] for r in REGISTERS});s.memory.store(NATIVE_GLOBALS,claripy.Concat(*(i['callback_'+k] for k in KEYS[:10])))
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('full',(False,True))
def test_equivalence(full):
 i=inputs('exploding_'+str(full));assert_pathwise_equivalent(assembly(i,full),native(i,full),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'HandleExplodingAnimation');assert linked_bytes(ROM,l,52)==bytes.fromhex('f0f3a721eacf1167d0fad2cf28092119d01167d0facccffe782803fe99c01acb77c02afe08c87efe08c8fa5fd0a7c03e05ea5bcc')
