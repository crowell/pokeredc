from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xEFFF;DELAYFLAGS=0xd358;STATUS4=0xd72e
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;delay:claripy.ast.BV;status4:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Setup(angr.SimProcedure):
 def run(self):
  # xor a ; ld [wLetterPrintingDelayFlags],a ; ld hl,wStatusFlags4 ;
  # set BIT_LINK_CONNECTED,[hl] ; ld hl,LinkMenuEmptyText
  self.state.regs.a=claripy.BVV(0,8);self.state.regs.f=claripy.BVV(0x40,8)
  self.state.memory.store(DELAYFLAGS,claripy.BVV(0,8))
  old=self.state.memory.load(STATUS4,1);self.state.regs.hl=claripy.Concat(claripy.BVV(0xd7,8),claripy.BVV(0x2e,8))
  self.state.memory.store(STATUS4,old|0x80)
  self.state.regs.hl=claripy.Concat(claripy.BVV(0x6b,8),claripy.BVV(0x20,8));self.jump(DONE)
def _assembly(v):
 l=symbol_location(SYMBOLS,'LinkMenu');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});p.hook(l.address,Setup(),length=12);s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v);s.memory.store(DELAYFLAGS,v['delay']);s.memory.store(STATUS4,v['status4']);m=p.factory.simulation_manager(s);m.explore(find=DONE);assert not m.errored;return [Endpoint(**assembly_registers(x),delay=x.memory.load(DELAYFLAGS,1),status4=x.memory.load(STATUS4,1),constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(v):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);f=p.loader.find_symbol('port_link_menu_private');assert f;s=p.factory.call_state(f.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,v);s.memory.store(NATIVE_STATE+8,v['delay']);s.memory.store(NATIVE_STATE+9,v['status4']);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [Endpoint(**native_registers(x,NATIVE_STATE),delay=x.memory.load(NATIVE_STATE+8,1),status4=x.memory.load(NATIVE_STATE+9,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='rom')
def test_link_menu_private_pathwise_equivalence():
 v=symbolic_registers('link_menu');v['delay']=claripy.BVS('link_menu_delay',8);v['status4']=claripy.BVS('link_menu_status4',8);assert_pathwise_equivalent(_assembly(v),_native(v),REGISTERS+('delay','status4'))
