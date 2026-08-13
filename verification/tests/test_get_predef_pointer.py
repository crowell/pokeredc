from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AddRegister,Sm83IncRegister,Sm83LoadAImmediate,Sm83StoreAAtHlIncrement,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff
ID=0xcc4e;SAVED=(0xcc4f,0xcc50,0xcc51,0xcc52,0xcc53,0xcc54);BANK=0xd0b7;KEYS=('predef_id','saved_h','saved_l','saved_d','saved_e','saved_b','saved_c','predef_bank','fetched_bank','fetched_pointer_low','fetched_pointer_high')
class Fetch(angr.SimProcedure):
 def __init__(self,n,key):super().__init__();self.n=n;self.key=key
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)  # type: ignore[override]
class StoreC(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.memory.store(self.state.regs.hl,self.state.regs.c);self.jump(self.n)  # type: ignore[override]
class IncDe(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.de=self.state.regs.de+1;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 return i
def assembly(i):
 l=symbol_location(SYMBOLS,'GetPredefPointer');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address
 p.hook(q+1,Sm83StoreAImmediate(SAVED[0],q+4),length=3);p.hook(q+5,Sm83StoreAImmediate(SAVED[1],q+8),length=3)
 for o in (12,14,16):p.hook(q+o,Sm83StoreAAtHlIncrement(q+o+1),length=1)
 p.hook(q+17,StoreC(q+18),length=1);p.hook(q+24,Sm83LoadAImmediate(ID,q+27),length=3);p.hook(q+28,Sm83AddRegister('a',q+29),length=1);p.hook(q+29,Sm83AddRegister('e',q+30),length=1);p.hook(q+33,Sm83IncRegister('d',q+34),length=1);p.hook(q+34,Sm83AddHlRegisterPair('de',q+35),length=1);p.hook(q+37,Fetch(q+38,'fetched_bank'),length=1);p.hook(q+38,Sm83StoreAImmediate(BANK,q+41),length=3);p.hook(q+41,IncDe(q+42),length=1);p.hook(q+42,Fetch(q+43,'fetched_pointer_low'),length=1);p.hook(q+44,IncDe(q+45),length=1);p.hook(q+45,Fetch(q+46,'fetched_pointer_high'),length=1)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.memory.store(ID,i['predef_id']);s.memory.store(BANK,i['predef_bank'])
 for a,k in zip(SAVED,KEYS[1:7]):s.memory.store(a,i[k])
 for k in KEYS:s.globals[k]=i[k]
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');ends=collect_returns(p,s,RETURN)
 return [E(**assembly_registers(x),memory=claripy.Concat(x.memory.load(ID,1),*(x.memory.load(a,1) for a in SAVED),x.memory.load(BANK,1),i['fetched_bank'],i['fetched_pointer_low'],i['fetched_pointer_high']),constraints=tuple(x.solver.constraints)) for x in ends]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_get_predef_pointer');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('predef_pointer');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'GetPredefPointer');assert linked_bytes(ROM,l,48)==bytes.fromhex('7cea4fcc7dea50cc2151cc7a227b2278227121797e110000fa4ecc5f87835f30011419545d1aeab7d0131a6f131a67c9')
