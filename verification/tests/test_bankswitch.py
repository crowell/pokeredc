from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,sm83_flags_to_z80,symbol_location,z80_flags_to_sm83
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;NATIVE_CALLBACK=0x100100;NATIVE_BANKS=0x100200;STACK=0xd000;RETURN=0xffff;DONE=0xefff
KEYS=('loaded_rom_bank','mapper_bank','saved_a','saved_f')
class ReadBank(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=self.state.globals['loaded_rom_bank'];self.jump(self.n)  # type: ignore[override]
class WriteBank(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.jump(self.n)  # type: ignore[override]
class SaveAf(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['saved_a']=self.state.regs.a;self.state.globals['saved_f']=z80_flags_to_sm83(self.state.regs.f);self.jump(self.n)  # type: ignore[override]
class RestoreAfToBc(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.b=self.state.globals['saved_a'];self.state.regs.c=self.state.globals['saved_f'];self.jump(self.n)  # type: ignore[override]
class IgnorePush(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)  # type: ignore[override]
class Boundary(angr.SimProcedure):
 def __init__(self,n=None):super().__init__();self.n=n
 def run(self):
  if self.n is None:self.jump(DONE);return  # type: ignore[override]
  cb=self.state.globals['callback']
  for r in REGISTERS:setattr(self.state.regs,r,sm83_flags_to_z80(cb[r]) if r=='f' else cb[r])
  self.state.globals['loaded_rom_bank']=cb['loaded_rom_bank'];self.state.globals['mapper_bank']=cb['mapper_bank'];self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 cb=symbolic_registers(f'{p}_callback')
 for r,v in cb.items():i[f'callback_{r}']=v
 for k in KEYS[:2]:i[f'callback_{k}']=claripy.BVS(f'{p}_callback_{k}',8)
 return i
def project():
 l=symbol_location(SYMBOLS,'Bankswitch');return l,angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
def setup(s,i):
 set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
 s.globals['callback']={r:i[f'callback_{r}'] for r in REGISTERS}|{k:i[f'callback_{k}'] for k in KEYS[:2]};s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
def endpoint(x):return E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[k] for k in KEYS)),constraints=tuple(x.solver.constraints))
def hooks(p,q,boundary):
 p.hook(q,ReadBank(q+2),length=2);p.hook(q+2,SaveAf(q+3),length=1);p.hook(q+4,WriteBank('loaded_rom_bank',q+6),length=2);p.hook(q+6,WriteBank('mapper_bank',q+9),length=3);p.hook(q+12,IgnorePush(q+13),length=1);p.hook(q+13,boundary,length=1)
def begin(i):
 l,p=project();q=l.address;hooks(p,q,Boundary());s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=DONE);return [endpoint(m.found[0])]
def ret(i):
 l,p=project();q=l.address;p.hook(q+14,RestoreAfToBc(q+15),length=1);p.hook(q+16,WriteBank('loaded_rom_bank',q+18),length=2);p.hook(q+18,WriteBank('mapper_bank',q+21),length=3);s=p.factory.blank_state(addr=q+14);setup(s,i);return [endpoint(x) for x in collect_returns(p,s,RETURN)]
def full(i):
 l,p=project();q=l.address;hooks(p,q,Boundary(q+14));p.hook(q+14,RestoreAfToBc(q+15),length=1);p.hook(q+16,WriteBank('loaded_rom_bank',q+18),length=2);p.hook(q+18,WriteBank('mapper_bank',q+21),length=3);s=p.factory.blank_state(addr=q);setup(s,i);return [endpoint(x) for x in collect_returns(p,s,RETURN)]
def native(symbol,i,whole=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(symbol);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE,NATIVE_CALLBACK,NATIVE_BANKS) if whole else p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)))
 if whole:
  store_native_registers(s,NATIVE_CALLBACK,{r:i[f'callback_{r}'] for r in REGISTERS});s.memory.store(NATIVE_BANKS,claripy.Concat(i['callback_loaded_rom_bank'],i['callback_mapper_bank']))
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('asm,symbol',((begin,'port_bankswitch_begin'),(ret,'port_bankswitch_return')))
def test_phases(asm,symbol):
 i=inputs(symbol);assert_pathwise_equivalent(asm(i),native(symbol,i),(*REGISTERS,'memory'))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_full():
 i=inputs('bankswitch');assert_pathwise_equivalent(full(i),native('port_bankswitch',i,True),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'Bankswitch');assert linked_bytes(ROM,l,22)==bytes.fromhex('f0b8f578e0b8ea002001e435c5e9c178e0b8ea0020c9');assert symbol_location(SYMBOLS,'hLoadedROMBank').address==0xffb8
