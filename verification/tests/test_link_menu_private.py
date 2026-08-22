from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import rom_window,symbol_location
from verification.harness.sm83_shims import Sm83SetAtHl,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xEFFF
DELAYFLAGS=0xd358;STATUS4=0xd72e;PRINTTEXT=0x3c49;SAVETILES=0x3719;TEXTBOXBORDER=0x3b19;UPDATESPRITES=0x3581;PLACESTRING=0x3d0b;HANDLEMENUINPUT=0x3abe
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;delay:claripy.ast.BV;status4:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Boundary(angr.SimProcedure):
 def run(self):self.jump(DONE)
def _assembly(v):
 l=symbol_location(SYMBOLS,'LinkMenu');q=l.address
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
 # Real instructions execute; each callee entry is an immediate-return boundary.
 p.hook(q+1,Sm83StoreAImmediate(DELAYFLAGS,q+4),length=3)   # ld [wLetterPrintingDelayFlags],a
 p.hook(q+7,Sm83SetAtHl(7,q+9),length=2)                    # set BIT_LINK_CONNECTED,[hl]
 p.hook(PRINTTEXT,Boundary(),length=1)
 p.hook(SAVETILES,Boundary(),length=1)
 p.hook(TEXTBOXBORDER,Boundary(),length=1)
 p.hook(UPDATESPRITES,Boundary(),length=1)
 p.hook(PLACESTRING,Boundary(),length=1)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,v)
 s.memory.store(DELAYFLAGS,v['delay']);s.memory.store(STATUS4,v['status4'])
 m=p.factory.simulation_manager(s);m.explore(find=DONE);assert not m.errored
 return [Endpoint(**assembly_registers(x),delay=x.memory.load(DELAYFLAGS,1),status4=x.memory.load(STATUS4,1),constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(v):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);f=p.loader.find_symbol('port_link_menu_private');assert f
 s=p.factory.call_state(f.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,v)
 s.memory.store(NATIVE_STATE+8,v['delay']);s.memory.store(NATIVE_STATE+9,v['status4'])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [Endpoint(**native_registers(x,NATIVE_STATE),delay=x.memory.load(NATIVE_STATE+8,1),status4=x.memory.load(NATIVE_STATE+9,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='rom')
def test_link_menu_private_pathwise_equivalence():
 v=symbolic_registers('link_menu');v['delay']=claripy.BVS('link_menu_delay',8);v['status4']=claripy.BVS('link_menu_status4',8)
 assert_pathwise_equivalent(_assembly(v),_native(v),REGISTERS+('delay','status4'))
