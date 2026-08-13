from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;NATIVE_CALLBACK=0x100100;NATIVE_WRITES=0x100200;DONE=0xefff
KEYS=('product_high','product_low','written_high','written_low','popped_d','popped_e','popped_h','popped_l','dispatched')
class Read(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)  # type: ignore[override]
class Write(angr.SimProcedure):
 def __init__(self,key,n,hli=False):super().__init__();self.key=key;self.n=n;self.hli=hli
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.state.regs.hl=self.state.regs.hl+(1 if self.hli else 0);self.jump(self.n)  # type: ignore[override]
class Pop(angr.SimProcedure):
 def __init__(self,pair,n):super().__init__();self.pair=pair;self.n=n
 def run(self):
  for r in self.pair:setattr(self.state.regs,r,self.state.globals['popped_'+r])
  self.jump(self.n)  # type: ignore[override]
class Boundary(angr.SimProcedure):
 def __init__(self,full):super().__init__();self.full=full
 def run(self):
  self.state.globals['dispatched']=claripy.BVV(1,8)
  if self.full:
   cb=self.state.globals['callback']
   for r in REGISTERS:setattr(self.state.regs,r,sm83_flags_to_z80(cb[r]) if r=='f' else cb[r])
   self.state.globals['written_high']=cb['written_high'];self.state.globals['written_low']=cb['written_low']
  self.jump(DONE)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 for r,v in symbolic_registers(p+'_callback').items():i['callback_'+r]=v
 i['callback_written_high']=claripy.BVS(p+'_callback_high',8);i['callback_written_low']=claripy.BVS(p+'_callback_low',8);return i
def assembly(symbol,i,full):
 l=symbol_location(SYMBOLS,symbol);tail=symbol_location(SYMBOLS,symbol+'Done').address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q,Read('product_high',q+2),length=2);p.hook(q+2,Write('written_high',q+3,hli=True),length=1);p.hook(q+3,Read('product_low',q+5),length=2);p.hook(q+5,Write('written_low',q+6),length=1)
 if symbol=='UpdateStat':p.hook(q+6,Pop('hl',q+7),length=1)
 else:p.hook(q+6,Pop('de',q+7),length=1);p.hook(q+7,Pop('hl',q+8),length=1)
 p.hook(tail,Boundary(full));s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
 s.globals['dispatched']=claripy.BVV(0,8);s.globals['callback']={r:i['callback_'+r] for r in REGISTERS}|{'written_high':i['callback_written_high'],'written_low':i['callback_written_low']};m=p.factory.simulation_manager(s);m.explore(find=DONE);return [E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[k] for k in KEYS)),constraints=tuple(x.solver.constraints)) for x in m.found]
def native(symbol,i,full):
 base='port_'+''.join(('_'+c.lower() if c.isupper() else c) for c in symbol).lstrip('_');name=base if full else base+'_begin';p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE,NATIVE_CALLBACK,NATIVE_WRITES) if full else p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)))
 if full:store_native_registers(s,NATIVE_CALLBACK,{r:i['callback_'+r] for r in REGISTERS});s.memory.store(NATIVE_WRITES,claripy.Concat(i['callback_written_high'],i['callback_written_low']))
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('symbol',('UpdateStat','UpdateLoweredStat'))
@pytest.mark.parametrize('full',(False,True))
def test_equivalence(symbol,full):
 i=inputs(symbol+str(full));assert_pathwise_equivalent(assembly(symbol,i,full),native(symbol,i,full),(*REGISTERS,'memory'))
def test_exact_prefixes():
 a=symbol_location(SYMBOLS,'UpdateStat');assert linked_bytes(ROM,a,7)==bytes.fromhex('f09722f09877e1');b=symbol_location(SYMBOLS,'UpdateLoweredStat');assert linked_bytes(ROM,b,8)==bytes.fromhex('f09722f09877d1e1')
