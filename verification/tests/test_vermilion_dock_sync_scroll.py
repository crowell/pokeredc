from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xefff;KEYS=('ly','scx')
class Bound(angr.SimProcedure):
 def run(self):self.jump(DONE)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 return i
def assembly(part,i):
 l=symbol_location(SYMBOLS,'VermilionDock_SyncScrollWithLY');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address
 if part=='first':start=q;p.hook(q+3,Bound(),length=3)
 else:start=q+6;p.hook(q+10,Bound(),length=2)
 s=p.factory.blank_state(addr=start);set_assembly_registers(s,i);m=p.factory.simulation_manager(s);m.explore(find=DONE);mem=claripy.Concat(i['ly'],i['scx']);return [E(**assembly_registers(x),memory=mem,constraints=tuple(x.solver.constraints)) for x in m.found]
def native(symbol,i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(symbol);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('part,symbol',(('first','port_vermilion_dock_sync_scroll_first_setup'),('second','port_vermilion_dock_sync_scroll_second_setup')))
def test_equivalence(part,symbol):
 i=inputs('dock_sync_'+part);assert_pathwise_equivalent(assembly(part,i),native(symbol,i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'VermilionDock_SyncScrollWithLY');assert linked_bytes(ROM,l,24)==bytes.fromhex('622e50cd865c26002e80f044bd20fb7ce043f044bc28fbc9')
