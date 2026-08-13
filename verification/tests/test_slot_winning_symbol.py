from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AddImmediate,Sm83IncRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff
class ReadWinning(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=self.state.globals['winning_symbol'];self.jump(self.n)  # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,index,n,immediate=None,delta=0):super().__init__();self.index=index;self.n=n;self.immediate=immediate;self.delta=delta
 def run(self):
  self.state.globals['writes'][self.index]=claripy.BVV(self.immediate,8) if self.immediate is not None else self.state.regs.a;self.state.regs.hl=self.state.regs.hl+self.delta;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p);i['winning_symbol']=claripy.BVS(p+'_winning',8);i['writes']=claripy.BVS(p+'_writes',40);return i
def assembly(i):
 l=symbol_location(SYMBOLS,'SlotMachine_PrintWinningSymbol');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q+3,ReadWinning(q+6),length=3);p.hook(q+6,Sm83AddImmediate(0x25,q+8),length=2);p.hook(q+8,Store(0,q+9,delta=1),length=1);p.hook(q+9,Sm83IncRegister('a',q+10),length=1);p.hook(q+10,Store(1,q+11,delta=-1),length=1);p.hook(q+11,Sm83IncRegister('a',q+12),length=1);p.hook(q+15,Sm83AddHlRegisterPair('de',q+16),length=1);p.hook(q+16,Store(2,q+17,delta=1),length=1);p.hook(q+17,Sm83IncRegister('a',q+18),length=1);p.hook(q+18,Store(3,q+19),length=1);p.hook(q+22,Store(4,q+24,immediate=0xee),length=2);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.globals['winning_symbol']=i['winning_symbol'];s.globals['writes']=[i['writes'][39-j*8:32-j*8] for j in range(5)];s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');return [E(**assembly_registers(x),memory=claripy.Concat(x.globals['winning_symbol'],*x.globals['writes']),constraints=tuple(x.solver.constraints)) for x in collect_returns(p,s,RETURN)]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_slot_machine_print_winning_symbol');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(i['winning_symbol'],i['writes']));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,6),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('slot_winning');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'SlotMachine_PrintWinningSymbol');assert linked_bytes(ROM,l,25)==bytes.fromhex('21bac4fa41cdc625223c323c11ecff19223c7721f2c436eec9');assert symbol_location(SYMBOLS,'wSlotMachineWinningSymbol').address==0xcd41
