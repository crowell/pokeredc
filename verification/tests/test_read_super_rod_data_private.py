from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xEFFF;CURMAP=0xd35e
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;cur_map:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Setup(angr.SimProcedure):
 def run(self):
  self.state.regs.a=self.state.memory.load(CURMAP,1);self.state.regs.d=claripy.BVV(0,8);self.state.regs.e=claripy.BVV(3,8);self.state.regs.h=claripy.BVV(0x69,8);self.state.regs.l=claripy.BVV(0x19,8);self.jump(DONE)
def _assembly(v):
 l=symbol_location(SYMBOLS,'ReadSuperRodData');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});p.hook(l.address,Setup(),length=9);s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v);s.memory.store(CURMAP,v['cur_map']);m=p.factory.simulation_manager(s);m.explore(find=DONE);assert not m.errored;return [Endpoint(**assembly_registers(x),cur_map=x.memory.load(CURMAP,1),constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(v):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);f=p.loader.find_symbol('port_read_super_rod_data_private');assert f;s=p.factory.call_state(f.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,v);s.memory.store(NATIVE_STATE+8,v['cur_map']);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [Endpoint(**native_registers(x,NATIVE_STATE),cur_map=x.memory.load(NATIVE_STATE+8,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='rom')
def test_read_super_rod_data_private_pathwise_equivalence():
 v=symbolic_registers('super_rod');v['cur_map']=claripy.BVS('super_rod_map',8);assert_pathwise_equivalent(_assembly(v),_native(v),REGISTERS+('cur_map',))
