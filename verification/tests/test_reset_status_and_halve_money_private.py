from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xEFFF
ADDR=[0xcf0b,0xd700,0xd057,0xd35d,0xcf10,0xffb4,0xcc57,0xcd60,0xff9f,0xffa0,0xffa1]
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;values:tuple[claripy.ast.BV,...];constraints:tuple[claripy.ast.Bool,...]
class Setup(angr.SimProcedure):
 def run(self):
  self.state.regs.a=claripy.BVV(0,8);self.state.regs.f=claripy.BVV(0,8)
  for addr in ADDR:self.state.memory.store(addr,claripy.BVV(0,8))
  self.jump(DONE)
def _assembly(v):
 l=symbol_location(SYMBOLS,'ResetStatusAndHalveMoneyOnBlackout');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});p.hook(l.address,Setup(),length=30);s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v)
 for addr,name in zip(ADDR,['battle_result','walk_bike_surf','in_battle','map_pal_offset','npc_function','joy_held','npc_pointer','misc_flags','money0','money1','money2']):s.memory.store(addr,v[name])
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=1);assert not m.errored;return [Endpoint(**assembly_registers(x),values=tuple(x.memory.load(a,1) for a in ADDR),constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(v):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);f=p.loader.find_symbol('port_reset_status_and_halve_money_private');assert f;s=p.factory.call_state(f.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,v)
 for off,name in enumerate(['battle_result','walk_bike_surf','in_battle','map_pal_offset','npc_function','joy_held','npc_pointer','misc_flags','money0','money1','money2']):s.memory.store(NATIVE_STATE+8+off,v[name])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [Endpoint(**native_registers(x,NATIVE_STATE),values=tuple(x.memory.load(NATIVE_STATE+8+i,1) for i in range(11)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='rom')
def test_reset_status_and_halve_money_private_pathwise_equivalence():
 v=symbolic_registers('blackout_reset');
 for name in ['battle_result','walk_bike_surf','in_battle','map_pal_offset','npc_function','joy_held','npc_pointer','misc_flags','money0','money1','money2']:v[name]=claripy.BVS('blackout_'+name,8)
 assert_pathwise_equivalent(_assembly(v),_native(v),REGISTERS)
