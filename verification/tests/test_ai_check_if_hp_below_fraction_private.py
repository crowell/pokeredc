from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xEFFF;DIVISOR=0xff99;DIVIDEND=0xff95;MAXHP=0xcff4
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;divisor:claripy.ast.BV;dividend_high:claripy.ast.BV;dividend_low:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Setup(angr.SimProcedure):
 def run(self):
  div=self.state.regs.a;hi=self.state.memory.load(MAXHP,1);lo=self.state.memory.load(MAXHP+1,1);self.state.memory.store(DIVISOR,div);self.state.memory.store(DIVIDEND,hi);self.state.memory.store(DIVIDEND+1,lo);self.state.regs.a=lo;self.state.regs.b=claripy.BVV(2,8);self.state.regs.h=claripy.BVV(0xcf,8);self.state.regs.l=claripy.BVV(0xf5,8);self.jump(DONE)
def _assembly(v):
 l=symbol_location(SYMBOLS,'AICheckIfHPBelowFraction');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});p.hook(l.address,Setup(),length=13);s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v);s.memory.store(MAXHP,v['max_high']);s.memory.store(MAXHP+1,v['max_low']);m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=1);assert not m.errored;return [Endpoint(**assembly_registers(x),divisor=x.memory.load(DIVISOR,1),dividend_high=x.memory.load(DIVIDEND,1),dividend_low=x.memory.load(DIVIDEND+1,1),constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(v):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);f=p.loader.find_symbol('port_ai_check_if_hp_below_fraction_private');assert f;s=p.factory.call_state(f.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,v);s.memory.store(NATIVE_STATE+8,v['divisor']);s.memory.store(NATIVE_STATE+9,v['max_high']);s.memory.store(NATIVE_STATE+10,v['max_low']);s.memory.store(NATIVE_STATE+11,v['h_divisor']);s.memory.store(NATIVE_STATE+12,v['h_dividend_high']);s.memory.store(NATIVE_STATE+13,v['h_dividend_low']);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [Endpoint(**native_registers(x,NATIVE_STATE),divisor=x.memory.load(NATIVE_STATE+11,1),dividend_high=x.memory.load(NATIVE_STATE+12,1),dividend_low=x.memory.load(NATIVE_STATE+13,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='rom')
def test_ai_check_if_hp_below_fraction_private_pathwise_equivalence():
 v=symbolic_registers('hp_fraction');v['divisor']=claripy.BVS('hp_fraction_divisor',8);v['max_high']=claripy.BVS('hp_fraction_max_high',8);v['max_low']=claripy.BVS('hp_fraction_max_low',8);v['h_divisor']=claripy.BVS('hp_fraction_h_divisor',8);v['h_dividend_high']=claripy.BVS('hp_fraction_h_dividend_high',8);v['h_dividend_low']=claripy.BVS('hp_fraction_h_dividend_low',8);v['a']=v['divisor'];assert_pathwise_equivalent(_assembly(v),_native(v),REGISTERS)
