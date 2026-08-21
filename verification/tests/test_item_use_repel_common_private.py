from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xEFFF;BATTLE=0xd057;REPEL=0xd0db
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;battle:claripy.ast.BV;repel:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Entry(angr.SimProcedure):
 def __init__(self,zero):super().__init__();self.zero=zero
 def run(self):
  battle=self.state.memory.load(BATTLE,1);self.state.regs.a=battle;self.state.regs.f=claripy.BVV(0x40 if self.zero else 0,8)
  if self.zero:self.state.memory.store(REPEL,self.state.regs.b)
  self.jump(DONE)
def _assembly(v):
 l=symbol_location(SYMBOLS,'ItemUseRepelCommon');out=[]
 for zero in (True,False):
  p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});p.hook(l.address,Entry(zero),length=6);s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v);s.memory.store(BATTLE,v['battle']);s.memory.store(REPEL,v['repel']);s.add_constraints(v['battle']==0 if zero else v['battle']!=0);m=p.factory.simulation_manager(s);m.explore(find=DONE);assert not m.errored;out.extend([Endpoint(**assembly_registers(x),battle=x.memory.load(BATTLE,1),repel=x.memory.load(REPEL,1),constraints=tuple(x.solver.constraints)) for x in m.found])
 return out
def _native(v):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);f=p.loader.find_symbol('port_item_use_repel_common_private');assert f;s=p.factory.call_state(f.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,v);s.memory.store(NATIVE_STATE+8,v['battle']);s.memory.store(NATIVE_STATE+9,v['repel']);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [Endpoint(**native_registers(x,NATIVE_STATE),battle=x.memory.load(NATIVE_STATE+8,1),repel=x.memory.load(NATIVE_STATE+9,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='rom')
def test_item_use_repel_common_private_pathwise_equivalence():
 v=symbolic_registers('repel');v['battle']=claripy.BVS('repel_battle',8);v['repel']=claripy.BVS('repel_steps',8);assert_pathwise_equivalent(_assembly(v),_native(v),REGISTERS+('battle','repel'))
