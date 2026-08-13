from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location,z80_flags_to_sm83
from verification.harness.sm83_shims import Sm83OrRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xefff
KEYS=('rom_bank_temp','loaded_rom_bank','mapper_bank','saved_a','saved_f','memory0','memory1','memory2')
def addresses(i):
 de=claripy.Concat(i['d'],i['e']);return (claripy.Concat(i['h'],i['l']),de,de+1)
def aliases(i):
 a=addresses(i);return tuple(claripy.Or(a[x]!=a[y],i[f'memory{x}']==i[f'memory{y}']) for x in range(3) for y in range(x))
def read(s,target):
 a=s.globals['addresses'];m=s.globals['memory'];v=m[0]
 for x in range(1,3):v=claripy.If(a[x]==target,m[x],v)
 return v
def write(s,target,value):
 a=s.globals['addresses'];m=s.globals['memory'];s.globals['memory']=[claripy.If(a[x]==target,value,m[x]) for x in range(3)]
class ReadKey(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)  # type: ignore[override]
class WriteKey(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.jump(self.n)  # type: ignore[override]
class SaveAf(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['saved_a']=self.state.regs.a;self.state.globals['saved_f']=z80_flags_to_sm83(self.state.regs.f);self.jump(self.n)  # type: ignore[override]
class RestoreAf(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=self.state.globals['saved_a'];self.state.regs.f=sm83_flags_to_z80(self.state.globals['saved_f']);self.jump(self.n)  # type: ignore[override]
class Fetch(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  target=self.state.regs.hl;self.state.regs.a=read(self.state,target);self.state.regs.hl=target+1;self.jump(self.n)  # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):write(self.state,self.state.regs.de,self.state.regs.a);self.jump(self.n)  # type: ignore[override]
class Bound(angr.SimProcedure):
 def run(self):self.state.globals['result']=claripy.If(self.state.regs.bc==0,claripy.BVV(1,8),claripy.BVV(0,8));self.jump(DONE)  # type: ignore[override]
class Stop(angr.SimProcedure):
 def run(self):self.jump(DONE)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:
  i[k]=claripy.Concat(claripy.BVS(f'{p}_{k}_flags',4),claripy.BVV(0,4)) if k=='saved_f' else claripy.BVS(f'{p}_{k}',8)
 return i
def project():
 l=symbol_location(SYMBOLS,'FarCopyDataDouble');return l,angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
def setup(s,i,with_alias=False):
 set_assembly_registers(s,i)
 for k in KEYS[:5]:s.globals[k]=i[k]
 s.globals['addresses']=addresses(i);s.globals['memory']=[i[f'memory{x}'] for x in range(3)];s.globals['result']=claripy.BVV(0,8)
 if with_alias:s.solver.add(*aliases(i))
def endpoint(x,i,with_alias=False):
 constraints=(aliases(i) if with_alias else ())+tuple(x.solver.constraints);return E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[k] for k in KEYS[:5]),*x.globals['memory']),result=x.globals['result'],constraints=constraints)
def entry(i):
 l,p=project();q=l.address;p.hook(q,WriteKey('rom_bank_temp',q+2),length=2);p.hook(q+2,ReadKey('loaded_rom_bank',q+4),length=2);p.hook(q+4,SaveAf(q+5),length=1);p.hook(q+5,ReadKey('rom_bank_temp',q+7),length=2);p.hook(q+7,WriteKey('loaded_rom_bank',q+9),length=2);p.hook(q+9,WriteKey('mapper_bank',q+12),length=3);p.hook(q+12,Stop());s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=DONE);return [endpoint(m.found[0],i)]
def step(i):
 l,p=project();q=l.address+12;p.hook(q,Fetch(q+1),length=1);p.hook(q+1,Store(q+2),length=1);p.hook(q+3,Store(q+4),length=1);p.hook(q+7,Sm83OrRegister('b',q+8),length=1);p.hook(q+8,Bound(),length=2);s=p.factory.blank_state(addr=q);setup(s,i,True);m=p.factory.simulation_manager(s);m.explore(find=DONE);return [endpoint(m.found[0],i,True)]
def finish(i):
 l,p=project();q=l.address+22;p.hook(q,RestoreAf(q+1),length=1);p.hook(q+1,WriteKey('loaded_rom_bank',q+3),length=2);p.hook(q+3,WriteKey('mapper_bank',q+6),length=3);p.hook(q+6,Stop());s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=DONE);return [endpoint(m.found[0],i)]
def native(symbol,i,with_alias=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(symbol);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)))
 if with_alias:s.solver.add(*aliases(i))
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),result=x.regs.rax[7:0] if symbol.endswith('_step') else claripy.BVV(0,8),constraints=(aliases(i) if with_alias else ())+tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('asm,symbol,alias',((entry,'port_far_copy_data_double_begin',False),(step,'port_far_copy_data_double_step',True),(finish,'port_far_copy_data_double_finish',False)))
def test_equivalence(asm,symbol,alias):
 i=inputs(symbol);assert_pathwise_equivalent(asm(i),native(symbol,i,alias),(*REGISTERS,'memory','result'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'FarCopyDataDouble');assert linked_bytes(ROM,l,29)==bytes.fromhex('e08bf0b8f5f08be0b8ea00202a121312130b79b020f6f1e0b8ea0020c9')
