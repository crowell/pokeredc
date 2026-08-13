from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83BitAtHl,Sm83SetAtHl
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff
class StoreScript(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['current_script']=self.state.regs.a;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p);i['event_flags']=claripy.BVS(p+'_events',8);i['current_script']=claripy.BVS(p+'_script',8);return i
def assembly(i):
 l=symbol_location(SYMBOLS,'VermilionCityLeftSSAnneCallbackScript');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q+3,Sm83BitAtHl(2,q+5),length=2);p.hook(q+6,Sm83BitAtHl(3,q+8),length=2);p.hook(q+8,Sm83SetAtHl(3,q+10),length=2);p.hook(q+13,StoreScript(q+16),length=3);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.memory.store(0xd803,i['event_flags']);s.globals['current_script']=i['current_script'];s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');return [E(**assembly_registers(x),memory=claripy.Concat(x.memory.load(0xd803,1),x.globals['current_script']),constraints=tuple(x.solver.constraints)) for x in collect_returns(p,s,RETURN)]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_vermilion_city_left_ss_anne_callback');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(i['event_flags'],i['current_script']));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,2),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('vermilion_ss_anne');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'VermilionCityLeftSSAnneCallbackScript');assert linked_bytes(ROM,l,17)==bytes.fromhex('2103d8cb56c8cb5ecbdec03e02ea2ad6c9');assert symbol_location(SYMBOLS,'wVermilionCityCurScript').address==0xd62a
