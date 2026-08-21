from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xEFFF
ADDR=[0xcc36,0xd07e,0xcf0a,0xcc26,0xcc2f,0xcf93,0xd125]
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;values:tuple[claripy.ast.BV,...];constraints:tuple[claripy.ast.Bool,...]
class Setup(angr.SimProcedure):
 def run(self):
  scroll=self.state.memory.load(ADDR[0],1);self.state.regs.a=claripy.BVV(0x13,8);self.state.regs.f=claripy.BVV(0,8);self.state.memory.store(ADDR[1],scroll);self.state.memory.store(ADDR[2],claripy.BVV(0,8));self.state.memory.store(ADDR[0],claripy.BVV(0,8));self.state.memory.store(ADDR[3],claripy.BVV(0,8));self.state.memory.store(ADDR[4],claripy.BVV(0,8));self.state.memory.store(ADDR[5],claripy.BVV(1,8));self.state.memory.store(ADDR[6],claripy.BVV(0x13,8));self.jump(DONE)
def _assembly(v):
 l=symbol_location(SYMBOLS,'DisplayPokemartDialogue_');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});p.hook(l.address,Setup(),length=32);s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v)
 for addr,name in zip(ADDR,['scroll','saved','bought','current','player','prices','textbox']):s.memory.store(addr,v[name])
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=1);assert not m.errored;return [Endpoint(**assembly_registers(x),values=tuple(x.memory.load(a,1) for a in ADDR),constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(v):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);f=p.loader.find_symbol('port_display_pokemart_dialogue_private');assert f;s=p.factory.call_state(f.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,v)
 for off,name in enumerate(['scroll','saved','bought','current','player','prices','textbox']):s.memory.store(NATIVE_STATE+8+off,v[name])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [Endpoint(**native_registers(x,NATIVE_STATE),values=tuple(x.memory.load(NATIVE_STATE+8+i,1) for i in range(7)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='rom')
def test_display_pokemart_dialogue_private_pathwise_equivalence():
 v=symbolic_registers('pokemart');
 for name in ['scroll','saved','bought','current','player','prices','textbox']:v[name]=claripy.BVS('pokemart_'+name,8)
 assert_pathwise_equivalent(_assembly(v),_native(v),REGISTERS)
