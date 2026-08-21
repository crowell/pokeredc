from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xEFFF;FACE=0xc109;TILESET=0xd367;INTERACT=0xffdb
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;facing:claripy.ast.BV;tileset:claripy.ast.BV;interacted:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Setup(angr.SimProcedure):
 def run(self):
  face=self.state.memory.load(FACE,1);tile=self.state.memory.load(TILESET,1);self.state.regs.a=claripy.If(face==4,tile,face);self.state.memory.store(INTERACT,claripy.If(face==4,self.state.memory.load(INTERACT,1),claripy.BVV(0xff,8)));self.jump(DONE)
def _assembly(v):
 l=symbol_location(SYMBOLS,'PrintBookshelfText');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});p.hook(l.address,Setup(),length=10);s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v);s.memory.store(FACE,v['facing']);s.memory.store(TILESET,v['tileset']);s.memory.store(INTERACT,v['interacted']);m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=1);assert not m.errored;return [Endpoint(**assembly_registers(x),facing=x.memory.load(FACE,1),tileset=x.memory.load(TILESET,1),interacted=x.memory.load(INTERACT,1),constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(v):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);f=p.loader.find_symbol('port_print_bookshelf_text_private');assert f;s=p.factory.call_state(f.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,v)
 for off,name in enumerate(['facing','tileset','interacted']):s.memory.store(NATIVE_STATE+8+off,v[name])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [Endpoint(**native_registers(x,NATIVE_STATE),facing=x.memory.load(NATIVE_STATE+8,1),tileset=x.memory.load(NATIVE_STATE+9,1),interacted=x.memory.load(NATIVE_STATE+10,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='rom')
def test_print_bookshelf_text_private_pathwise_equivalence():
 v=symbolic_registers('bookshelf');v['facing']=claripy.BVS('bookshelf_facing',8);v['tileset']=claripy.BVS('bookshelf_tileset',8);v['interacted']=claripy.BVS('bookshelf_interacted',8);assert_pathwise_equivalent(_assembly(v),_native(v),('a','interacted'))
