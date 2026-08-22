from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xEFFF;HOF=0xcc5b;HOF_SPECIES=0xcd3d;PARTY=0xcf91;SPECIES=0xd0b5;BATTLE2=0xcfd9;PALETTE=0xcf1d;HOF_LEVEL=0xcd3f
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;t0:claripy.ast.BV;t1:claripy.ast.BV;t2:claripy.ast.BV;t3:claripy.ast.BV;t4:claripy.ast.BV;t5:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Setup(angr.SimProcedure):
 def run(self):
  sp=self.state.memory.load(HOF,1);lvl=self.state.memory.load(HOF+1,1)
  self.state.regs.a=lvl;self.state.regs.d=claripy.BVV(0xcd,8);self.state.regs.e=claripy.BVV(0x6d,8);self.state.regs.b=claripy.BVV(0,8);self.state.regs.c=claripy.BVV(11,8)
  self.state.memory.store(HOF_SPECIES,sp);self.state.memory.store(PARTY,sp);self.state.memory.store(SPECIES,sp);self.state.memory.store(BATTLE2,sp);self.state.memory.store(PALETTE,sp);self.state.memory.store(HOF_LEVEL,lvl)
  self.jump(DONE)
def _assembly(v):
 l=symbol_location(SYMBOLS,'LeaguePCShowMon');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});p.hook(l.address,Setup(),length=40);s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v);s.memory.store(HOF,v['t0']);s.memory.store(HOF+1,v['t1']);m=p.factory.simulation_manager(s);m.explore(find=DONE);assert not m.errored;x=m.found[0]
 outs=(HOF_SPECIES,PARTY,SPECIES,BATTLE2,PALETTE,HOF_LEVEL)
 return [Endpoint(**assembly_registers(x),**{f't{i}':x.memory.load(outs[i],1) for i in range(6)},constraints=tuple(x.solver.constraints))]
def _native(v):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);f=p.loader.find_symbol('port_league_pc_show_mon_private');assert f;s=p.factory.call_state(f.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,v);s.memory.store(NATIVE_STATE+8,v['t0']);s.memory.store(NATIVE_STATE+9,v['t1']);m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [Endpoint(**native_registers(x,NATIVE_STATE),**{f't{i}':x.memory.load(NATIVE_STATE+10+i,1) for i in range(6)},constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='rom')
def test_league_pc_show_mon_private_pathwise_equivalence():
 v=symbolic_registers('league_mon')
 for k in ('t0','t1','t2','t3','t4','t5'):v[k]=claripy.BVS('league_mon_'+k,8)
 assert_pathwise_equivalent(_assembly(v),_native(v),REGISTERS+tuple(f't{i}' for i in range(6)))
