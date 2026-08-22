from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83CpImmediate,Sm83DecRegister,Sm83Scf
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff;KEYS=('ram_enable','bank_mode','ram_bank')
class XorA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=claripy.BVV(0,8);self.state.regs.f=claripy.BVV(0x40,8);self.jump(self.n)  # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.jump(self.n)  # type: ignore[override]
class FetchName(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  i=self.state.globals['index'];self.state.regs.a=self.state.globals['name'][i];self.state.globals['index']=i+1;self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 i['name']=claripy.BVS(p+'_name',88);return i
def assembly(i):
 l=symbol_location(SYMBOLS,'CheckForPlayerNameInSRAM');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q+2,Store('ram_enable',q+5),length=3);p.hook(q+7,Store('bank_mode',q+10),length=3);p.hook(q+10,Store('ram_bank',q+13),length=3);p.hook(q+18,FetchName(q+19),length=1);p.hook(q+19,Sm83CpImmediate(0x50,q+21),length=2);p.hook(q+23,Sm83DecRegister('b',q+24),length=1);p.hook(q+26,XorA(q+27),length=1);p.hook(q+27,Store('ram_enable',q+30),length=3);p.hook(q+30,Store('bank_mode',q+33),length=3);p.hook(q+33,Sm83AndImmediate(0xff,q+34),length=1);p.hook(q+35,XorA(q+36),length=1);p.hook(q+36,Store('ram_enable',q+39),length=3);p.hook(q+39,Store('bank_mode',q+42),length=3);p.hook(q+42,Sm83Scf(q+43),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
 s.globals['name']=[i['name'][87-j*8:80-j*8] for j in range(11)];s.globals['index']=0;s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');return [E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[k] for k in KEYS),*x.globals['name']),constraints=tuple(x.solver.constraints)) for x in collect_returns(p,s,RETURN)]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_check_for_player_name_in_sram');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for k in KEYS:s.memory.store(NATIVE_STATE+8+KEYS.index(k),i[k])
 for j in range(11):s.memory.store(NATIVE_STATE+11+j,i['name'][87-j*8:80-j*8])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=claripy.Concat(*(x.memory.load(NATIVE_STATE+8+n,1) for n in range(14))),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('player_name_sram');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'CheckForPlayerNameInSRAM');assert linked_bytes(ROM,l,44)==bytes.fromhex('3e0aea00003e01ea0060ea0040060b2198a52afe50280c0520f8afea0000ea0060a7c9afea0000ea006037c9');assert symbol_location(SYMBOLS,'sPlayerName').address==0xa598
