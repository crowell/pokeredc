from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83LoadAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xeffc
NAMES=('wPredefHL','wPredefHL+1','wPredefDE','wPredefDE+1','wPredefBC','wPredefBC+1')
class Boundary(angr.SimProcedure):
 def run(self):self.jump(DONE)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs():
 i=symbolic_registers('divide_bcd_predef3')
 for n in range(6):i[f'memory{n}']=claripy.BVS(f'divide_bcd_predef3_memory{n}',8)
 return i
def addr(name):return symbol_location(SYMBOLS,name[:-2]).address+1 if name.endswith('+1') else symbol_location(SYMBOLS,name).address
def assembly(i):
 l=symbol_location(SYMBOLS,'DivideBCDPredef3');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q});g=symbol_location(SYMBOLS,'GetPredefRegisters').address
 for off,n in ((0,3),(4,7),(8,11),(12,15),(16,19),(20,23)):p.hook(g+off,Sm83LoadAImmediate(addr(NAMES[off//4]),g+n),length=3)
 p.hook(symbol_location(SYMBOLS,'DivideBCD').address,Boundary(),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for n,name in enumerate(NAMES):s.memory.store(addr(name),i[f'memory{n}'])
 m=p.factory.simulation_manager(s);m.explore(find=DONE);return [E(**assembly_registers(x),memory=claripy.Concat(*(x.memory.load(addr(n),1) for n in NAMES)),constraints=tuple(x.solver.constraints)) for x in m.found]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_divide_bcd_predef3');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[f'memory{n}'] for n in range(6))));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,6),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs();assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'DivideBCDPredef3');assert linked_bytes(ROM,l,3)==bytes.fromhex('cd943e')
