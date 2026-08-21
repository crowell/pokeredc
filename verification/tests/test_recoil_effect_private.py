from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xEFFF
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Setup(angr.SimProcedure):
 def run(self):
  w=self.state.memory.load(0xfff3,1);pm=self.state.memory.load(0xcfd2,1);em=self.state.memory.load(0xcfcc,1);self.state.regs.a=claripy.If(w==0,pm,em);self.state.regs.h=claripy.If(w==0,claripy.BVV(0xd0,8),claripy.BVV(0xcf,8));self.state.regs.l=claripy.If(w==0,claripy.BVV(0x23,8),claripy.BVV(0xf4,8));self.state.regs.f=claripy.If(w==0,claripy.BVV(0x50,8),claripy.BVV(0x10,8));self.jump(DONE)
def _assembly(v):
 l=symbol_location(SYMBOLS,'RecoilEffect_');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});p.hook(l.address,Setup(),length=0x11);s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v);s.memory.store(0xfff3,v['whose_turn']);s.memory.store(0xcfd2,v['player_move_num']);s.memory.store(0xcfcc,v['enemy_move_num']);m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=1);assert not m.errored;return [Endpoint(**assembly_registers(x),constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(v):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);f=p.loader.find_symbol('port_recoil_effect_private');assert f;s=p.factory.call_state(f.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,v);s.memory.store(NATIVE_STATE+8,v['whose_turn']);s.memory.store(NATIVE_STATE+9,v['player_move_num']);s.memory.store(NATIVE_STATE+10,v['enemy_move_num']);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [Endpoint(**native_registers(x,NATIVE_STATE),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='rom')
def test_recoil_effect_private_pathwise_equivalence():
 v=symbolic_registers('recoil');v['whose_turn']=claripy.BVS('recoil_whose',8);v['player_move_num']=claripy.BVS('recoil_player_move',8);v['enemy_move_num']=claripy.BVS('recoil_enemy_move',8);assert_pathwise_equivalent(_assembly(v),_native(v),REGISTERS)
