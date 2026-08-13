from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AndImmediate,Sm83CpImmediate,Sm83IncRegister,Sm83LoadAImmediate,Sm83SubImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff;CURRENT=0xd5a0
class FetchLow(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=self.state.globals['fetched_low'];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
class FetchHigh(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.h=self.state.globals['fetched_high'];self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in ('current_box','fetched_low','fetched_high'):i[n]=claripy.BVS(f'{p}_{n}',8)
 return i
def assembly(i):
 l=symbol_location(SYMBOLS,'GetBoxSRAMLocation');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q+3,Sm83LoadAImmediate(CURRENT,q+6),length=3);p.hook(q+6,Sm83AndImmediate(0x7f,q+8),length=2);p.hook(q+8,Sm83CpImmediate(6,q+10),length=2);p.hook(q+14,Sm83IncRegister('b',q+15),length=1);p.hook(q+15,Sm83SubImmediate(6,q+17),length=2);p.hook(q+20,Sm83AddHlRegisterPair('de',q+21),length=1);p.hook(q+21,Sm83AddHlRegisterPair('de',q+22),length=1);p.hook(q+22,FetchLow(q+23),length=1);p.hook(q+23,FetchHigh(q+24),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.memory.store(CURRENT,i['current_box']);s.globals['fetched_low']=i['fetched_low'];s.globals['fetched_high']=i['fetched_high'];s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');ends=collect_returns(p,s,RETURN)
 return [E(**assembly_registers(x),memory=claripy.Concat(x.memory.load(CURRENT,1),i['fetched_low'],i['fetched_high']),constraints=tuple(x.solver.constraints)) for x in ends]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_get_box_sram_location');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(i['current_box'],i['fetched_low'],i['fetched_high']));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,3),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('box_sram');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'GetBoxSRAMLocation');assert linked_bytes(ROM,l,26)==bytes.fromhex('219578faa0d5e67ffe060602380304d6065f160019192a666fc9')
