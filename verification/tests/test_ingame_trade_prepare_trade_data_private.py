from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xEFFF;GIVE=0xcd0f;RECEIVE=0xcd34;PLAYER=0xcd3d;ENEMY=0xcd3e
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;give:claripy.ast.BV;receive:claripy.ast.BV;player:claripy.ast.BV;enemy:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Setup(angr.SimProcedure):
 def run(self):
  give=self.state.memory.load(GIVE,1);recv=self.state.memory.load(RECEIVE,1);self.state.regs.a=recv;self.state.regs.h=claripy.BVV(0xcd,8);self.state.regs.l=claripy.BVV(0x3e,8);self.state.memory.store(PLAYER,give);self.state.memory.store(ENEMY,recv);self.jump(DONE)
def _assembly(v):
 l=symbol_location(SYMBOLS,'InGameTrade_PrepareTradeData');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});p.hook(l.address,Setup(),length=11);s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v)
 for addr,name in [(GIVE,'give'),(RECEIVE,'receive'),(PLAYER,'player'),(ENEMY,'enemy')]:s.memory.store(addr,v[name])
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=1);assert not m.errored;return [Endpoint(**assembly_registers(x),give=x.memory.load(GIVE,1),receive=x.memory.load(RECEIVE,1),player=x.memory.load(PLAYER,1),enemy=x.memory.load(ENEMY,1),constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(v):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);f=p.loader.find_symbol('port_ingame_trade_prepare_trade_data_private');assert f;s=p.factory.call_state(f.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,v)
 for off,name in enumerate(['give','receive','player','enemy']):s.memory.store(NATIVE_STATE+8+off,v[name])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [Endpoint(**native_registers(x,NATIVE_STATE),give=x.memory.load(NATIVE_STATE+8,1),receive=x.memory.load(NATIVE_STATE+9,1),player=x.memory.load(NATIVE_STATE+10,1),enemy=x.memory.load(NATIVE_STATE+11,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='rom')
def test_ingame_trade_prepare_trade_data_private_pathwise_equivalence():
 v=symbolic_registers('trade_prepare');
 for name in ['give','receive','player','enemy']:v[name]=claripy.BVS('trade_prepare_'+name,8)
 assert_pathwise_equivalent(_assembly(v),_native(v),REGISTERS)
