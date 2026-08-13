from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83DecRegister,Sm83IncRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff
DMA_CODE=bytes.fromhex('3ec3e0463e283d20fdc9')
class HliFetch(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=self.state.memory.load(self.state.regs.hl,1);self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
class StoreC(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.memory.store(claripy.ZeroExt(8,self.state.regs.c)|0xff00,self.state.regs.a);self.jump(self.n)  # type: ignore[override]
class StoreDma(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['dma']=self.state.regs.a;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def copy_assembly(i):
 l=symbol_location(SYMBOLS,'WriteDMACodeToHRAM');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q+7,HliFetch(q+8),length=1);p.hook(q+8,StoreC(q+9),length=1);p.hook(q+9,Sm83IncRegister('c',q+10),length=1);p.hook(q+10,Sm83DecRegister('b',q+11),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.memory.store(0xff80,i['memory']);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');return [E(**assembly_registers(x),memory=x.memory.load(0xff80,10),constraints=tuple(x.solver.constraints)) for x in collect_returns(p,s,RETURN)]
def dma_assembly(i):
 l=symbol_location(SYMBOLS,'DMARoutine');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q+2,StoreDma(q+4),length=2);p.hook(q+6,Sm83DecRegister('a',q+7),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.globals['dma']=i['memory'];s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');return [E(**assembly_registers(x),memory=x.globals['dma'],constraints=tuple(x.solver.constraints)) for x in collect_returns(p,s,RETURN)]
def native(symbol,size,i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(symbol);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i['memory']);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,size),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_copy_equivalence():
 i=symbolic_registers('dma_copy');i['memory']=claripy.BVS('dma_copy_hram',80);assert_pathwise_equivalent(copy_assembly(i),native('port_write_dma_code_to_hram',10,i),(*REGISTERS,'memory'))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_routine_equivalence():
 i=symbolic_registers('hdma');i['memory']=claripy.BVS('hdma_register',8);assert_pathwise_equivalent(dma_assembly(i),native('port_hdma_routine',1,i),(*REGISTERS,'memory'))
def test_exact_bodies():
 l=symbol_location(SYMBOLS,'WriteDMACodeToHRAM');assert linked_bytes(ROM,l,14)==bytes.fromhex('0e80060a21fb4b2ae20c0520fac9');d=symbol_location(SYMBOLS,'DMARoutine');assert linked_bytes(ROM,d,10)==DMA_CODE;assert symbol_location(SYMBOLS,'hDMARoutine').address==0xff80
