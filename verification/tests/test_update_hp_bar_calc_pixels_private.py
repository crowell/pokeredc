from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xEFFF;MAX=0xcee9;OLD=0xceeb;NEW=0xceed
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;max_low:claripy.ast.BV;max_high:claripy.ast.BV;old_low:claripy.ast.BV;old_high:claripy.ast.BV;new_low:claripy.ast.BV;new_high:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Setup(angr.SimProcedure):
 def run(self):
  ml=self.state.memory.load(MAX,1);mh=self.state.memory.load(MAX+1,1);ol=self.state.memory.load(OLD,1);oh=self.state.memory.load(OLD+1,1);nl=self.state.memory.load(NEW,1);nh=self.state.memory.load(NEW+1,1);self.state.regs.e=ml;self.state.regs.d=mh;self.state.regs.c=ol;self.state.regs.b=oh;self.state.regs.l=nl;self.state.regs.h=nh;self.jump(DONE)
def _assembly(v):
 l=symbol_location(SYMBOLS,'UpdateHPBar_CalcOldNewHPBarPixels');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});p.hook(l.address,Setup(),length=17);s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v)
 for addr,name in [(MAX,'max_low'),(MAX+1,'max_high'),(OLD,'old_low'),(OLD+1,'old_high'),(NEW,'new_low'),(NEW+1,'new_high')]:s.memory.store(addr,v[name])
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=1);assert not m.errored;return [Endpoint(**assembly_registers(x),max_low=x.memory.load(MAX,1),max_high=x.memory.load(MAX+1,1),old_low=x.memory.load(OLD,1),old_high=x.memory.load(OLD+1,1),new_low=x.memory.load(NEW,1),new_high=x.memory.load(NEW+1,1),constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(v):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);f=p.loader.find_symbol('port_update_hp_bar_calc_pixels_private');assert f;s=p.factory.call_state(f.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,v)
 for off,name in enumerate(['max_low','max_high','old_low','old_high','new_low','new_high']):s.memory.store(NATIVE_STATE+8+off,v[name])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [Endpoint(**native_registers(x,NATIVE_STATE),max_low=x.memory.load(NATIVE_STATE+8,1),max_high=x.memory.load(NATIVE_STATE+9,1),old_low=x.memory.load(NATIVE_STATE+10,1),old_high=x.memory.load(NATIVE_STATE+11,1),new_low=x.memory.load(NATIVE_STATE+12,1),new_high=x.memory.load(NATIVE_STATE+13,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='rom')
def test_update_hp_bar_calc_pixels_private_pathwise_equivalence():
 v=symbolic_registers('hp_pixels');
 for name in ['max_low','max_high','old_low','old_high','new_low','new_high']:v[name]=claripy.BVS('hp_pixels_'+name,8)
 assert_pathwise_equivalent(_assembly(v),_native(v),REGISTERS)
