from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddImmediate,Sm83IncRegister,Sm83LoadAHighImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff
def addresses(i):
 h=i['h'];l=i['l'];o=i['offset'];third=claripy.Concat(h+1,o+2);return (claripy.Concat(h,l),claripy.Concat(h,l+1),third,third+1)
def alias_constraints(i):
 a=addresses(i);return tuple(claripy.Or(a[x]!=a[y],i[f'memory{x}']==i[f'memory{y}']) for x in range(4) for y in range(x))
class Store(angr.SimProcedure):
 def __init__(self,n,value,inc=False):super().__init__();self.n=n;self.value=value;self.inc=inc
 def run(self):
  a=self.state.globals['addresses'];m=list(self.state.globals['memory']);target=self.state.regs.hl;value=claripy.BVV(self.value,8)
  for x in range(4):m[x]=claripy.If(a[x]==target,value,m[x])
  self.state.globals['memory']=m
  if self.inc:self.state.regs.hl=target+1
  self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p);i['offset']=claripy.BVS(p+'_offset',8)
 for n in range(4):i[f'memory{n}']=claripy.BVS(f'{p}_memory{n}',8)
 return i
def assembly(i):
 l=symbol_location(SYMBOLS,'InitializeSpriteStatus');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q,Store(q+2,1),length=2);p.hook(q+2,Sm83IncRegister('l',q+3),length=1);p.hook(q+3,Store(q+5,0xff),length=2);p.hook(q+5,Sm83IncRegister('h',q+6),length=1);p.hook(q+6,Sm83LoadAHighImmediate(0xda,q+8),length=2);p.hook(q+8,Sm83AddImmediate(2,q+10),length=2);p.hook(q+13,Store(q+14,8,True),length=1);p.hook(q+14,Store(q+15,8),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.memory.store(0xffda,i['offset']);s.globals['addresses']=addresses(i);s.globals['memory']=[i[f'memory{n}'] for n in range(4)];s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');ends=collect_returns(p,s,RETURN)
 return [E(**assembly_registers(x),memory=claripy.Concat(*x.globals['memory']),constraints=alias_constraints(i)+tuple(x.solver.constraints)) for x in ends]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_initialize_sprite_status');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(i['offset'],*(i[f'memory{n}'] for n in range(4))));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+9,4),constraints=alias_constraints(i)+tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('init_sprite_status');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'InitializeSpriteStatus');assert linked_bytes(ROM,l,16)==bytes.fromhex('36012c36ff24f0dac6026f3e082277c9')
