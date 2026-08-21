from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xEFFF;MENU=0xcc26;WHICH=0xcf92
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;menu:claripy.ast.BV;which:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Setup(angr.SimProcedure):
 def run(self):
  menu=self.state.memory.load(MENU,1);self.state.regs.a=menu;self.state.memory.store(WHICH,menu);self.jump(DONE)
def _assembly(v):
 l=symbol_location(SYMBOLS,'TradeCenter_DisplayStats');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});p.hook(l.address,Setup(),length=6);s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v);s.memory.store(MENU,v['menu']);s.memory.store(WHICH,v['which']);m=p.factory.simulation_manager(s);m.explore(find=DONE);assert not m.errored;return [Endpoint(**assembly_registers(x),menu=x.memory.load(MENU,1),which=x.memory.load(WHICH,1),constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(v):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);f=p.loader.find_symbol('port_trade_center_display_stats_private');assert f;s=p.factory.call_state(f.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,v);s.memory.store(NATIVE_STATE+8,v['menu']);s.memory.store(NATIVE_STATE+9,v['which']);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [Endpoint(**native_registers(x,NATIVE_STATE),menu=x.memory.load(NATIVE_STATE+8,1),which=x.memory.load(NATIVE_STATE+9,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='rom')
def test_trade_center_display_stats_private_pathwise_equivalence():
 v=symbolic_registers('trade_stats');v['menu']=claripy.BVS('trade_stats_menu',8);v['which']=claripy.BVS('trade_stats_which',8);assert_pathwise_equivalent(_assembly(v),_native(v),REGISTERS+('menu','which'))
