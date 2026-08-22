from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xEFFF;OPTINIT=0xd08a;SAVE=0xd088
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;optinit:claripy.ast.BV;save:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Setup(angr.SimProcedure):
 def run(self):
  self.state.regs.a=claripy.BVV(1,8);self.state.regs.f=claripy.BVV(0x40,8);self.state.memory.store(OPTINIT,claripy.BVV(0,8));self.state.memory.store(SAVE,claripy.BVV(1,8));self.jump(DONE)
def _assembly(v):
 l=symbol_location(SYMBOLS,'MainMenu');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});p.hook(l.address,Setup(),length=12);s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v);s.memory.store(OPTINIT,v['optinit']);s.memory.store(SAVE,v['save']);m=p.factory.simulation_manager(s);m.explore(find=DONE);assert not m.errored;return [Endpoint(**assembly_registers(x),optinit=x.memory.load(OPTINIT,1),save=x.memory.load(SAVE,1),constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(v):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);f=p.loader.find_symbol('port_main_menu_private');assert f;s=p.factory.call_state(f.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,v);s.memory.store(NATIVE_STATE+8,v['optinit']);s.memory.store(NATIVE_STATE+9,v['save']);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [Endpoint(**native_registers(x,NATIVE_STATE),optinit=x.memory.load(NATIVE_STATE+8,1),save=x.memory.load(NATIVE_STATE+9,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='rom')
def test_main_menu_private_pathwise_equivalence():
 v=symbolic_registers('main_menu');v['optinit']=claripy.BVS('main_menu_optinit',8);v['save']=claripy.BVS('main_menu_save',8);assert_pathwise_equivalent(_assembly(v),_native(v),REGISTERS+('optinit','save'))
