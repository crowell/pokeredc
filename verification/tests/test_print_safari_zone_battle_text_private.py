from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xEFFF;BAIT=0xcce9;ROCK=0xcce8
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;bait:claripy.ast.BV;rock:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Setup(angr.SimProcedure):
 def run(self):
  bait=self.state.memory.load(BAIT,1);rock=self.state.memory.load(ROCK,1);old=claripy.If(bait!=0,bait,rock);result=old-1;self.state.regs.a=old;self.state.regs.f=claripy.If(bait!=0,claripy.BVV(0,8),claripy.BVV(0,8))|0x08|claripy.If((old&15)==0,claripy.BVV(0x10,8),claripy.BVV(0,8))|claripy.If(result==0,claripy.BVV(0x40,8),claripy.BVV(0,8));self.state.memory.store(BAIT,claripy.If(bait!=0,result,bait));self.state.memory.store(ROCK,claripy.If(bait!=0,rock,result));self.state.regs.h=claripy.If(bait!=0,claripy.BVV(0x42,8),claripy.If(result!=0,claripy.BVV(0x42,8),self.state.regs.h));self.state.regs.l=claripy.If(bait!=0,claripy.BVV(0xa7,8),claripy.If(result!=0,claripy.BVV(0xac,8),self.state.regs.l));self.jump(DONE)
def _assembly(v):
 l=symbol_location(SYMBOLS,'PrintSafariZoneBattleText');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});p.hook(l.address,Setup(),length=3);s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v);s.memory.store(BAIT,v['bait']);s.memory.store(ROCK,v['rock']);m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=1);assert not m.errored;return [Endpoint(**assembly_registers(x),bait=x.memory.load(BAIT,1),rock=x.memory.load(ROCK,1),constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(v):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);f=p.loader.find_symbol('port_print_safari_zone_battle_text_private');assert f;s=p.factory.call_state(f.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,v);s.memory.store(NATIVE_STATE+8,v['bait']);s.memory.store(NATIVE_STATE+9,v['rock']);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [Endpoint(**native_registers(x,NATIVE_STATE),bait=x.memory.load(NATIVE_STATE+8,1),rock=x.memory.load(NATIVE_STATE+9,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='rom')
def test_print_safari_zone_battle_text_private_pathwise_equivalence():
 v=symbolic_registers('safari_text');v['bait']=claripy.BVS('safari_bait',8);v['rock']=claripy.BVS('safari_rock',8);assert_pathwise_equivalent(_assembly(v),_native(v),REGISTERS)
