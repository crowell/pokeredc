from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
from verification.harness.sm83_shims import Sm83ResAtHl
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;NATIVE_CALLBACK=0x100100;NATIVE_EVENT=0x100200;DONE=0xefff
class Boundary(angr.SimProcedure):
 def run(self):
  cb=self.state.globals['callback']
  for r in REGISTERS:setattr(self.state.regs,r,sm83_flags_to_z80(cb[r]) if r=='f' else cb[r])
  self.state.globals['event_flags']=cb['event_flags'];self.state.globals['dispatched']=claripy.BVV(1,8);self.jump(DONE)  # type: ignore[override]
class BeginBoundary(angr.SimProcedure):
 def run(self):self.state.globals['dispatched']=claripy.BVV(1,8);self.jump(DONE)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p);i['event_flags']=claripy.BVS(p+'_events',8);i['dispatched']=claripy.BVS(p+'_dispatched',8)
 for r,v in symbolic_registers(p+'_callback').items():i['callback_'+r]=v
 i['callback_event_flags']=claripy.BVS(p+'_callback_events',8);return i
def assembly(i,full):
 l=symbol_location(SYMBOLS,'VictoryRoad2FResetBoulderEventScript');tail=symbol_location(SYMBOLS,'VictoryRoad2FCheckBoulderEventScript').address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q+3,Sm83ResAtHl(7,q+5),length=2);p.hook(tail,Boundary() if full else BeginBoundary());s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.memory.store(0xd869,i['event_flags']);s.globals['event_flags']=i['event_flags'];s.globals['dispatched']=claripy.BVV(0,8);s.globals['callback']={r:i['callback_'+r] for r in REGISTERS}|{'event_flags':i['callback_event_flags']};m=p.factory.simulation_manager(s);m.explore(find=DONE);return [E(**assembly_registers(x),memory=claripy.Concat(x.globals['event_flags'] if full else x.memory.load(0xd869,1),x.globals['dispatched']),constraints=tuple(x.solver.constraints)) for x in m.found]
def native(i,full):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);name='port_victory_road2f_reset_boulder_event' if full else 'port_victory_road2f_reset_boulder_event_begin';fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE,NATIVE_CALLBACK,NATIVE_EVENT) if full else p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(i['event_flags'],i['dispatched']))
 if full:store_native_registers(s,NATIVE_CALLBACK,{r:i['callback_'+r] for r in REGISTERS});s.memory.store(NATIVE_EVENT,i['callback_event_flags'])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,2),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('full',(False,True))
def test_equivalence(full):
 i=inputs('victory_reset_'+str(full));assert_pathwise_equivalent(assembly(i,full),native(i,full),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'VictoryRoad2FResetBoulderEventScript');assert linked_bytes(ROM,l,5)==bytes.fromhex('2169d8cbbe')
