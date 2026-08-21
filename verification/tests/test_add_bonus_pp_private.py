from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xEFFF;NORMAL=0xd000
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;normal:claripy.ast.BV;dividend0:claripy.ast.BV;dividend1:claripy.ast.BV;dividend2:claripy.ast.BV;dividend3:claripy.ast.BV;divisor:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Setup(angr.SimProcedure):
 def run(self):
  normal=self.state.memory.load(NORMAL,1);self.state.memory.store(NORMAL+1,claripy.BVV(0,8));self.state.memory.store(NORMAL+2,claripy.BVV(0,8));self.state.memory.store(NORMAL+3,claripy.BVV(0,8));self.state.memory.store(NORMAL+4,normal);self.state.memory.store(NORMAL+5,claripy.BVV(5,8));self.state.regs.a=claripy.BVV(5,8);self.state.regs.b=claripy.BVV(4,8);self.jump(DONE)
def _assembly(v):
 l=symbol_location(SYMBOLS,'AddBonusPP');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});p.hook(l.address,Setup(),length=17);s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v);s.memory.store(NORMAL,v['normal']);m=p.factory.simulation_manager(s);m.explore(find=DONE);assert not m.errored;return [Endpoint(**assembly_registers(x),normal=x.memory.load(NORMAL,1),dividend0=x.memory.load(NORMAL+1,1),dividend1=x.memory.load(NORMAL+2,1),dividend2=x.memory.load(NORMAL+3,1),dividend3=x.memory.load(NORMAL+4,1),divisor=x.memory.load(NORMAL+5,1),constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(v):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);f=p.loader.find_symbol('port_add_bonus_pp_private');assert f;s=p.factory.call_state(f.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,v)
 for i,key in enumerate(('normal','dividend0','dividend1','dividend2','dividend3','divisor')):s.memory.store(NATIVE_STATE+8+i,v[key])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [Endpoint(**native_registers(x,NATIVE_STATE),normal=x.memory.load(NATIVE_STATE+8,1),dividend0=x.memory.load(NATIVE_STATE+9,1),dividend1=x.memory.load(NATIVE_STATE+10,1),dividend2=x.memory.load(NATIVE_STATE+11,1),dividend3=x.memory.load(NATIVE_STATE+12,1),divisor=x.memory.load(NATIVE_STATE+13,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='rom')
def test_add_bonus_pp_private_pathwise_equivalence():
 v=symbolic_registers('add_bonus');v['normal']=claripy.BVS('add_bonus_normal',8);v['dividend0']=claripy.BVS('add_bonus_d0',8);v['dividend1']=claripy.BVS('add_bonus_d1',8);v['dividend2']=claripy.BVS('add_bonus_d2',8);v['dividend3']=claripy.BVS('add_bonus_d3',8);v['divisor']=claripy.BVS('add_bonus_divisor',8);v['d']=claripy.BVV(0xd0,8);v['e']=claripy.BVV(0,8);assert_pathwise_equivalent(_assembly(v),_native(v),REGISTERS+('normal','dividend0','dividend1','dividend2','dividend3','divisor'))
