from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xEFFF;TILES=0xcd3f
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;t0:claripy.ast.BV;t1:claripy.ast.BV;t2:claripy.ast.BV;t3:claripy.ast.BV;t4:claripy.ast.BV;t5:claripy.ast.BV;t6:claripy.ast.BV;t7:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Setup(angr.SimProcedure):
 def run(self):
  self.state.regs.d=claripy.BVV(0xcd,8);self.state.regs.e=claripy.BVV(0x3f,8);self.state.regs.h=claripy.BVV(0x6a,8);self.state.regs.l=claripy.BVV(0x96,8);self.state.regs.b=claripy.BVV(0,8);self.state.regs.c=claripy.BVV(8,8)
  for i,b in enumerate((0x20,0x28,0x30,0x38,0x40,0x48,0x50,0x58)):self.state.memory.store(TILES+i,claripy.BVV(b,8))
  self.jump(DONE)
def _assembly(v):
 l=symbol_location(SYMBOLS,'DrawBadges');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});p.hook(l.address,Setup(),length=8);s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v)
 for i in range(8):s.memory.store(TILES+i,v['tiles' if i==0 else f'tiles{i}'])
 m=p.factory.simulation_manager(s);m.explore(find=DONE);assert not m.errored;return [Endpoint(**assembly_registers(x),**{f't{i}':x.memory.load(TILES+i,1) for i in range(8)},constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(v):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);f=p.loader.find_symbol('port_draw_badges_private');assert f;s=p.factory.call_state(f.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,v)
 for i in range(8):s.memory.store(NATIVE_STATE+8+i,v['tiles' if i==0 else f'tiles{i}'])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [Endpoint(**native_registers(x,NATIVE_STATE),**{f't{i}':x.memory.load(NATIVE_STATE+8+i,1) for i in range(8)},constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='rom')
def test_draw_badges_private_pathwise_equivalence():
 v=symbolic_registers('draw_badges')
 for i in range(8):v['tiles' if i==0 else f'tiles{i}']=claripy.BVS(f'draw_badges_tile{i}',8) if i else claripy.BVS('draw_badges_tiles',8)
 assert_pathwise_equivalent(_assembly(v),_native(v),REGISTERS+tuple(f't{i}' for i in range(8)))
