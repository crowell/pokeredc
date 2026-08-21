from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xEFFF;AUTO=0xffba;WY=0xffb0;TEXTBOX=0xd125
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;auto:claripy.ast.BV;wy:claripy.ast.BV;textbox:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Setup(angr.SimProcedure):
 def run(self):
  self.state.regs.a=claripy.BVV(0x11,8);self.state.regs.f=claripy.BVV(0,8);self.state.memory.store(AUTO,claripy.BVV(1,8));self.state.memory.store(WY,claripy.BVV(0,8));self.state.memory.store(TEXTBOX,claripy.BVV(0x11,8));self.jump(DONE)
def _assembly(v):
 l=symbol_location(SYMBOLS,'DisplayMonFrontSpriteInBox');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});p.hook(l.address,Setup(),length=24);s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v);s.memory.store(AUTO,v['auto']);s.memory.store(WY,v['wy']);s.memory.store(TEXTBOX,v['textbox']);m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=1);assert not m.errored;return [Endpoint(**assembly_registers(x),auto=x.memory.load(AUTO,1),wy=x.memory.load(WY,1),textbox=x.memory.load(TEXTBOX,1),constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(v):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);f=p.loader.find_symbol('port_display_mon_front_sprite_in_box_private');assert f;s=p.factory.call_state(f.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,v);s.memory.store(NATIVE_STATE+8,v['auto']);s.memory.store(NATIVE_STATE+9,v['wy']);s.memory.store(NATIVE_STATE+10,v['textbox']);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [Endpoint(**native_registers(x,NATIVE_STATE),auto=x.memory.load(NATIVE_STATE+8,1),wy=x.memory.load(NATIVE_STATE+9,1),textbox=x.memory.load(NATIVE_STATE+10,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='rom')
def test_display_mon_front_sprite_in_box_private_pathwise_equivalence():
 v=symbolic_registers('sprite_box');v['auto']=claripy.BVS('sprite_box_auto',8);v['wy']=claripy.BVS('sprite_box_wy',8);v['textbox']=claripy.BVS('sprite_box_textbox',8);assert_pathwise_equivalent(_assembly(v),_native(v),REGISTERS)
