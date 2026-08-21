from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xEFFF;LINK=0xd12b;OPP=0xd059;COUNT=0xd89c;SPECIES=0xd89d
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;link:claripy.ast.BV;opponent:claripy.ast.BV;count:claripy.ast.BV;species:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Setup(angr.SimProcedure):
 def run(self):
  link=self.state.memory.load(LINK,1);self.state.regs.a=claripy.If(link==0,self.state.memory.load(OPP,1),self.state.regs.a);self.state.memory.store(COUNT,claripy.If(link==0,claripy.BVV(0,8),self.state.memory.load(COUNT,1)));self.state.memory.store(SPECIES,claripy.If(link==0,claripy.BVV(0xff,8),self.state.memory.load(SPECIES,1)));self.jump(DONE)
def _assembly(v):
 l=symbol_location(SYMBOLS,'ReadTrainer');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});p.hook(l.address,Setup(),length=3);s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v);s.memory.store(LINK,v['link']);s.memory.store(OPP,v['opponent']);s.memory.store(COUNT,v['count']);s.memory.store(SPECIES,v['species']);m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=1);assert not m.errored;return [Endpoint(**assembly_registers(x),link=x.memory.load(LINK,1),opponent=x.memory.load(OPP,1),count=x.memory.load(COUNT,1),species=x.memory.load(SPECIES,1),constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(v):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);f=p.loader.find_symbol('port_read_trainer_private');assert f;s=p.factory.call_state(f.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,v);s.memory.store(NATIVE_STATE+8,v['link']);s.memory.store(NATIVE_STATE+9,v['opponent']);s.memory.store(NATIVE_STATE+10,v['count']);s.memory.store(NATIVE_STATE+11,v['species']);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [Endpoint(**native_registers(x,NATIVE_STATE),link=x.memory.load(NATIVE_STATE+8,1),opponent=x.memory.load(NATIVE_STATE+9,1),count=x.memory.load(NATIVE_STATE+10,1),species=x.memory.load(NATIVE_STATE+11,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='rom')
def test_read_trainer_private_pathwise_equivalence():
 v=symbolic_registers('read_trainer');v['link']=claripy.BVS('read_trainer_link',8);v['opponent']=claripy.BVS('read_trainer_opponent',8);v['count']=claripy.BVS('read_trainer_count',8);v['species']=claripy.BVS('read_trainer_species',8);assert_pathwise_equivalent(_assembly(v),_native(v),REGISTERS)
