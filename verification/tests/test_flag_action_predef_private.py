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
  bit=self.state.regs.c;ptr=claripy.Concat(self.state.regs.h,self.state.regs.l);ptr=ptr+(claripy.ZeroExt(8,bit)>>3);self.state.regs.h=ptr[15:8];self.state.regs.l=ptr[7:0];self.state.regs.d=bit;self.state.regs.e=bit&7;self.jump(DONE)
def _assembly(v):
 l=symbol_location(SYMBOLS,'FlagActionPredef');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});p.hook(l.address,Setup(),length=21);s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v);s.memory.store(0xcc4f,v['h']);s.memory.store(0xcc50,v['l']);s.memory.store(0xcc51,v['d']);s.memory.store(0xcc52,v['e']);s.memory.store(0xcc53,v['c']);m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=1);assert not m.errored;return [Endpoint(**assembly_registers(x),constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(v):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);f=p.loader.find_symbol('port_flag_action_predef_private');assert f;s=p.factory.call_state(f.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,v);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [Endpoint(**native_registers(x,NATIVE_STATE),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='rom')
def test_flag_action_predef_private_pathwise_equivalence():
 v=symbolic_registers('flag_action');v['h']=claripy.BVS('flag_h',8);v['l']=claripy.BVS('flag_l',8);v['c']=claripy.BVS('flag_c',8);v['d']=v['d'];v['e']=v['e'];assert_pathwise_equivalent(_assembly(v),_native(v),('h','l','d','e'))
