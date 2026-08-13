from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83OrRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;NATIVE_CALLBACK=0x100100;NATIVE_GLOBALS=0x100200;STACK=0xd000;RETURN=0xffff;DONE=0xefff;KEYS=('hp_high','hp_low','tile0','tile1','tile2','dispatched')
class ReadHp(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)  # type: ignore[override]
class StoreHli(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
class StoreImmediate(angr.SimProcedure):
 def __init__(self,key,value,n):super().__init__();self.key=key;self.value=value;self.n=n
 def run(self):self.state.globals[self.key]=claripy.BVV(self.value,8);self.jump(self.n)  # type: ignore[override]
class Boundary(angr.SimProcedure):
 def __init__(self,full):super().__init__();self.full=full
 def run(self):
  self.state.globals['dispatched']=claripy.BVV(1,8)
  if self.full:
   cb=self.state.globals['callback']
   for r in REGISTERS:setattr(self.state.regs,r,sm83_flags_to_z80(cb[r]) if r=='f' else cb[r])
   for k in KEYS[:5]:self.state.globals[k]=cb[k]
  self.jump(DONE)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 for r,v in symbolic_registers(p+'_callback').items():i['callback_'+r]=v
 for k in KEYS[:5]:i['callback_'+k]=claripy.BVS(f'{p}_callback_{k}',8)
 return i
def assembly(i,full):
 l=symbol_location(SYMBOLS,'PrintStatusCondition');tail=symbol_location(SYMBOLS,'PrintStatusConditionNotFainted').address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q+3,ReadHp('hp_high',q+4),length=1);p.hook(q+6,ReadHp('hp_low',q+7),length=1);p.hook(q+7,Sm83OrRegister('b',q+8),length=1);p.hook(q+13,StoreHli('tile0',q+14),length=1);p.hook(q+16,StoreHli('tile1',q+17),length=1);p.hook(q+17,StoreImmediate('tile2',0x93,q+19),length=2);p.hook(q+19,Sm83AndImmediate(0xff,q+20),length=1);p.hook(tail,Boundary(full));s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
 s.globals['dispatched']=claripy.BVV(0,8)
 s.globals['callback']={r:i['callback_'+r] for r in REGISTERS}|{k:i['callback_'+k] for k in KEYS[:5]};s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');m=p.factory.simulation_manager(s);m.stashes['terminal']=[]
 while m.active:
  m.move(from_stash='active',to_stash='terminal',filter_func=lambda x:x.addr in (RETURN,DONE))
  if m.active:m.step()
 assert not m.errored;ends=m.terminal
 return [E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[k] for k in KEYS)),constraints=tuple(x.solver.constraints)) for x in ends]
def native(i,full):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_print_status_condition' if full else 'port_print_status_condition_begin');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE,NATIVE_CALLBACK,NATIVE_GLOBALS) if full else p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)))
 if full:store_native_registers(s,NATIVE_CALLBACK,{r:i['callback_'+r] for r in REGISTERS});s.memory.store(NATIVE_GLOBALS,claripy.Concat(*(i['callback_'+k] for k in KEYS[:5])))
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('full',(False,True))
def test_equivalence(full):
 i=inputs('print_status_'+str(full));assert_pathwise_equivalent(assembly(i,full),native(i,full),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'PrintStatusCondition');assert linked_bytes(ROM,l,21)==bytes.fromhex('d51b1b1a471b1ab0d1200a3e85223e8d223693a7c9');t=symbol_location(SYMBOLS,'PrintStatusConditionNotFainted');assert linked_bytes(ROM,t,21)==bytes.fromhex('f0b8f53e1de0b8ea0020cdde47c178e0b8ea0020c9')
