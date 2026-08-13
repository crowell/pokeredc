from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83OrRegister,Sm83SwapRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff
class Read(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)
class Write(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs():
 i=symbolic_registers('divide_bcd_by10')
 for n in ('d0','d1','d2'):i[n]=claripy.BVS('divide_bcd_by10_'+n,8)
 return i
def assembly(i):
 l=symbol_location(SYMBOLS,'DivideBCD_divDivisorBy10');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q})
 for off,key,nxt in ((0,'d2',2),(7,'d1',9),(18,'d1',20),(23,'d0',25),(34,'d0',36)):p.hook(q+off,Read(key,q+nxt),length=nxt-off)
 for off,key,nxt in ((11,'d1',13),(16,'d2',18),(27,'d0',29),(32,'d1',34),(38,'d0',40)):p.hook(q+off,Write(key,q+nxt),length=nxt-off)
 for off in (2,9,25):p.hook(q+off,Sm83SwapRegister('a',q+off+2),length=2)
 for off,imm in ((4,0x0f),(13,0xf0),(20,0x0f),(29,0xf0),(36,0x0f)):p.hook(q+off,Sm83AndImmediate(imm,q+off+2),length=2)
 for off in (15,31):p.hook(q+off,Sm83OrRegister('b',q+off+1),length=1)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for n in ('d0','d1','d2'):s.globals[n]=i[n]
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');return [E(**assembly_registers(x),memory=claripy.Concat(x.globals['d0'],x.globals['d1'],x.globals['d2']),constraints=tuple(x.solver.constraints)) for x in collect_returns(p,s,RETURN)]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_divide_bcd_div_divisor_by10');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(i['d0'],i['d1'],i['d2']));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,3),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs();assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'DivideBCD_divDivisorBy10');assert linked_bytes(ROM,l,41)==bytes.fromhex('f0a4cb37e60f47f0a3cb37e0a3e6f0b0e0a4f0a3e60f47f0a2cb37e0a2e6f0b0e0a3f0a2e60fe0a2c9')
