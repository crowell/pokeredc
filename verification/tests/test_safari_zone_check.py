from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83BitAtHl
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;NATIVE_CALLBACK=0x100100;NATIVE_GLOBALS=0x100200;DONE=0xefff;KEYS=('event_flags','safari_balls','destination')
class ReadBalls(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=self.state.globals['safari_balls'];self.jump(self.n)  # type: ignore[override]
class Boundary(angr.SimProcedure):
 def __init__(self,dest,full):super().__init__();self.dest=dest;self.full=full
 def run(self):
  self.state.globals['destination']=claripy.BVV(self.dest,8)
  if self.full:
   cb=self.state.globals['callback'][self.dest]
   for r in REGISTERS:setattr(self.state.regs,r,sm83_flags_to_z80(cb[r]) if r=='f' else cb[r])
   self.state.globals['event_flags']=cb['event_flags'];self.state.globals['safari_balls']=cb['safari_balls']
  self.jump(DONE)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 for d in (1,2):
  for r,v in symbolic_registers(f'{p}_callback{d}').items():i[f'callback{d}_{r}']=v
  for k in KEYS[:2]:i[f'callback{d}_{k}']=claripy.BVS(f'{p}_callback{d}_{k}',8)
 return i
def assembly(i,full):
 l=symbol_location(SYMBOLS,'SafariZoneCheck');still=symbol_location(SYMBOLS,'SafariZoneGameStillGoing').address;over=symbol_location(SYMBOLS,'SafariZoneGameOver').address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q+3,Sm83BitAtHl(7,q+5),length=2);p.hook(q+7,ReadBalls(q+10),length=3);p.hook(q+10,Sm83AndImmediate(0xff,q+11),length=1);p.hook(still,Boundary(1,full));p.hook(over,Boundary(2,full));s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.memory.store(0xd790,i['event_flags']);s.globals['event_flags']=i['event_flags'];s.globals['safari_balls']=i['safari_balls'];s.globals['destination']=i['destination'];s.globals['callback']={d:{r:i[f'callback{d}_{r}'] for r in REGISTERS}|{k:i[f'callback{d}_{k}'] for k in KEYS[:2]} for d in (1,2)};m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=10)
 return [E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[k] for k in KEYS)),constraints=tuple(x.solver.constraints)) for x in m.found]
def native(i,full):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_safari_zone_check' if full else 'port_safari_zone_check_begin');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE,NATIVE_CALLBACK,NATIVE_GLOBALS) if full else p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)))
 if full:
  for d in (1,2):store_native_registers(s,NATIVE_CALLBACK+(d-1)*8,{r:i[f'callback{d}_{r}'] for r in REGISTERS});s.memory.store(NATIVE_GLOBALS+(d-1)*2,claripy.Concat(*(i[f'callback{d}_{k}'] for k in KEYS[:2])))
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('full',(False,True))
def test_equivalence(full):
 i=inputs('safari_'+str(full));assert_pathwise_equivalent(assembly(i,full),native(i,full),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'SafariZoneCheck');assert linked_bytes(ROM,l,15)==bytes.fromhex('2190d7cb7e281cfa47daa7281b1814');assert symbol_location(SYMBOLS,'wNumSafariBalls').address==0xda47
