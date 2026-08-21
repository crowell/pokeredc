from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xEFFF
ITEM=0xcf7b;PTR=0xcf8b;CURRENT=0xcc26;SCROLL=0xcc36;PRICES=0xcf93;MENU=0xcf94
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;item_low:claripy.ast.BV;item_high:claripy.ast.BV;pointer_low:claripy.ast.BV;pointer_high:claripy.ast.BV;current:claripy.ast.BV;scroll:claripy.ast.BV;prices:claripy.ast.BV;menu:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Setup(angr.SimProcedure):
 def run(self):
  lo=self.state.memory.load(ITEM,1);hi=self.state.memory.load(ITEM+1,1);self.state.regs.h=claripy.BVV(0xcf,8);self.state.regs.l=claripy.BVV(0x7b,8);self.state.regs.a=claripy.BVV(4,8);self.state.regs.f=claripy.BVV(0,8);self.state.memory.store(PTR,lo);self.state.memory.store(PTR+1,hi);self.state.memory.store(CURRENT,claripy.BVV(0,8));self.state.memory.store(SCROLL,claripy.BVV(0,8));self.state.memory.store(PRICES,claripy.BVV(0,8));self.state.memory.store(MENU,claripy.BVV(4,8));self.jump(DONE)
def _assembly(v):
 l=symbol_location(SYMBOLS,'DisplayElevatorFloorMenu');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});p.hook(l.address,Setup(),length=36);s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v);s.memory.store(ITEM,v['item_low']);s.memory.store(ITEM+1,v['item_high']);m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=1);assert not m.errored;return [Endpoint(**assembly_registers(x),item_low=x.memory.load(ITEM,1),item_high=x.memory.load(ITEM+1,1),pointer_low=x.memory.load(PTR,1),pointer_high=x.memory.load(PTR+1,1),current=x.memory.load(CURRENT,1),scroll=x.memory.load(SCROLL,1),prices=x.memory.load(PRICES,1),menu=x.memory.load(MENU,1),constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(v):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);f=p.loader.find_symbol('port_display_elevator_floor_menu_private');assert f;s=p.factory.call_state(f.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,v)
 for off,name in enumerate(['item_low','item_high','pointer_low','pointer_high','current','scroll','prices','menu']):s.memory.store(NATIVE_STATE+8+off,v[name])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [Endpoint(**native_registers(x,NATIVE_STATE),item_low=x.memory.load(NATIVE_STATE+8,1),item_high=x.memory.load(NATIVE_STATE+9,1),pointer_low=x.memory.load(NATIVE_STATE+10,1),pointer_high=x.memory.load(NATIVE_STATE+11,1),current=x.memory.load(NATIVE_STATE+12,1),scroll=x.memory.load(NATIVE_STATE+13,1),prices=x.memory.load(NATIVE_STATE+14,1),menu=x.memory.load(NATIVE_STATE+15,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='rom')
def test_display_elevator_floor_menu_private_pathwise_equivalence():
 v=symbolic_registers('elevator');
 for name in ['item_low','item_high','pointer_low','pointer_high','current','scroll','prices','menu']:v[name]=claripy.BVS('elevator_'+name,8)
 assert_pathwise_equivalent(_assembly(v),_native(v),REGISTERS)
