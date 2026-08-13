from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xeffc
class ZeroA(angr.SimProcedure):
 def run(self):self.state.regs.a=0;self.state.regs.f=0x40;self.jump(DONE)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(i):
 l=symbol_location(SYMBOLS,'OakSpeechSlidePicRight');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q});p.hook(q+6,ZeroA(),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);m=p.factory.simulation_manager(s);m.explore(find=DONE);return [E(**assembly_registers(x),constraints=tuple(x.solver.constraints)) for x in m.found]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_oak_speech_slide_pic_right');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=symbolic_registers('oak_slide_right');assert_pathwise_equivalent(assembly(i),native(i),REGISTERS)
def test_exact_body():
 l=symbol_location(SYMBOLS,'OakSpeechSlidePicRight');assert linked_bytes(ROM,l,7)==bytes.fromhex('21f5c3117d06af')
