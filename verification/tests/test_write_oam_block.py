from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddRegister,Sm83SwapRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff
class WriteEntry(angr.SimProcedure):
 def run(self):
  i=self.state.globals['index'];self.state.globals[f'oam{i*4}']=self.state.regs.b;self.state.globals[f'oam{i*4+1}']=self.state.regs.c;self.state.regs.a=self.state.globals[f'source{i*2}'];self.state.globals[f'oam{i*4+2}']=self.state.regs.a;self.state.regs.a=self.state.globals[f'source{i*2+1}'];self.state.globals[f'oam{i*4+3}']=self.state.regs.a;self.state.regs.hl=self.state.regs.hl+4;self.state.regs.de=self.state.regs.de+2;self.state.globals['index']=i+1;target=self.state.memory.load(self.state.regs.sp,2,endness='Iend_LE');self.state.regs.sp=self.state.regs.sp+2;self.jump(target)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p);i['source']=claripy.BVS(p+'_source',64);i['oam']=claripy.BVS(p+'_oam',128);return i
def assembly(i):
 l=symbol_location(SYMBOLS,'WriteOAMBlock');entry=symbol_location(SYMBOLS,'WriteOAMBlock.writeOneEntry').address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q+2,Sm83SwapRegister('a',q+4),length=2);p.hook(q+11,Sm83AddRegister('c',q+12),length=1);p.hook(q+19,Sm83AddRegister('b',q+20),length=1);p.hook(q+26,Sm83AddRegister('c',q+27),length=1);p.hook(entry,WriteEntry());s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for j in range(8):s.globals[f'source{j}']=i['source'][63-j*8:56-j*8]
 for j in range(16):s.globals[f'oam{j}']=i['oam'][127-j*8:120-j*8]
 s.globals['index']=0;s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');return [E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[f'source{j}'] for j in range(8)),*(x.globals[f'oam{j}'] for j in range(16))),constraints=tuple(x.solver.constraints)) for x in collect_returns(p,s,RETURN)]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_write_oam_block');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(i['source'],i['oam']));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,24),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('write_oam_block');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'WriteOAMBlock');assert linked_bytes(ROM,l,39)==bytes.fromhex('26c3cb376fcdb33ac53e08814fcdb33ac13e088047cdb33a3e08814f702371231a13221a1322c9')
