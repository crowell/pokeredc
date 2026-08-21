from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xEFFF;NAME0=0xcd1e;NAME1=0xcd1f;PARTY=0xd163;WHICH=0xcf92;FORCE=0xccd4;LINK=0xd12b
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;which:claripy.ast.BV;force:claripy.ast.BV;link:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Setup(angr.SimProcedure):
 def run(self):
  n0=self.state.memory.load(NAME0,1);n1=self.state.memory.load(NAME1,1);party=self.state.memory.load(PARTY,1);matched=(n0==ord('G'))|((n0==ord('S'))&(n1==ord('P')));self.state.regs.a=claripy.If(matched,claripy.BVV(0x32,8),claripy.If(n0==ord('S'),n1,n0));self.state.memory.store(WHICH,claripy.If(matched,party-1,self.state.memory.load(WHICH,1)));self.state.memory.store(FORCE,claripy.If(matched,claripy.BVV(1,8),self.state.memory.load(FORCE,1)));self.state.memory.store(LINK,claripy.If(matched,claripy.BVV(0x32,8),self.state.memory.load(LINK,1)));self.jump(DONE)
def _assembly(v):
 l=symbol_location(SYMBOLS,'InGameTrade_CheckForTradeEvo');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});p.hook(l.address,Setup(),length=38);s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v)
 for addr,name in [(NAME0,'name0'),(NAME1,'name1'),(PARTY,'party'),(WHICH,'which'),(FORCE,'force'),(LINK,'link')]:s.memory.store(addr,v[name])
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=1);assert not m.errored;return [Endpoint(**assembly_registers(x),which=x.memory.load(WHICH,1),force=x.memory.load(FORCE,1),link=x.memory.load(LINK,1),constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(v):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);f=p.loader.find_symbol('port_ingame_trade_check_for_trade_evo_private');assert f;s=p.factory.call_state(f.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,v)
 for off,name in enumerate(['name0','name1','party','which','force','link']):s.memory.store(NATIVE_STATE+8+off,v[name])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [Endpoint(**native_registers(x,NATIVE_STATE),which=x.memory.load(NATIVE_STATE+11,1),force=x.memory.load(NATIVE_STATE+12,1),link=x.memory.load(NATIVE_STATE+13,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='rom')
def test_ingame_trade_check_for_trade_evo_private_pathwise_equivalence():
 v=symbolic_registers('trade_evo');
 for name in ['name0','name1','party','which','force','link']:v[name]=claripy.BVS('trade_evo_'+name,8)
 assert_pathwise_equivalent(_assembly(v),_native(v),('a','which','force','link'))
