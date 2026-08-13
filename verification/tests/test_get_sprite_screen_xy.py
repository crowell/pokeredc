from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddImmediate,Sm83AddRegister,Sm83AndImmediate,Sm83IncRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff
def addresses(i):
 d=i['d'];e=i['e'];return (claripy.Concat(d,e+2),claripy.Concat(d,e+4),claripy.BVV(0xff92,16),claripy.BVV(0xff91,16),claripy.Concat(d,e+8),claripy.Concat(d,e+9))
def alias_constraints(i):
 a=addresses(i);return tuple(claripy.Or(a[x]!=a[y],i[f'memory{x}']==i[f'memory{y}']) for x in range(6) for y in range(x))
class Read(angr.SimProcedure):
 def __init__(self,n,target=None):super().__init__();self.n=n;self.target=target
 def run(self):
  target=self.state.regs.de if self.target is None else claripy.BVV(self.target,16);a=self.state.globals['addresses'];m=self.state.globals['memory'];value=m[0]
  for x in range(1,6):value=claripy.If(a[x]==target,m[x],value)
  self.state.regs.a=value;self.jump(self.n)  # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,n,target=None):super().__init__();self.n=n;self.target=target
 def run(self):
  target=self.state.regs.de if self.target is None else claripy.BVV(self.target,16);a=self.state.globals['addresses'];m=self.state.globals['memory'];self.state.globals['memory']=[claripy.If(a[x]==target,self.state.regs.a,m[x]) for x in range(6)];self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for x in range(6):i[f'memory{x}']=claripy.BVS(f'{p}_memory{x}',8)
 return i
def assembly(i):
 l=symbol_location(SYMBOLS,'GetSpriteScreenXY');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address
 for o in (0,1,5,6,21):p.hook(q+o,Sm83IncRegister('e',q+o+1),length=1)
 p.hook(q+2,Read(q+3),length=1);p.hook(q+3,Store(q+5,0xff92),length=2);p.hook(q+7,Read(q+8),length=1);p.hook(q+8,Store(q+10,0xff91),length=2);p.hook(q+12,Sm83AddRegister('e',q+13),length=1);p.hook(q+14,Read(q+16,0xff92),length=2);p.hook(q+16,Sm83AddImmediate(4,q+18),length=2);p.hook(q+18,Sm83AndImmediate(0xf0,q+20),length=2);p.hook(q+20,Store(q+21),length=1);p.hook(q+22,Read(q+24,0xff91),length=2);p.hook(q+24,Sm83AndImmediate(0xf0,q+26),length=2);p.hook(q+26,Store(q+27),length=1)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.globals['addresses']=addresses(i);s.globals['memory']=[i[f'memory{x}'] for x in range(6)];s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');ends=collect_returns(p,s,RETURN)
 return [E(**assembly_registers(x),memory=claripy.Concat(*x.globals['memory']),constraints=alias_constraints(i)+tuple(x.solver.constraints)) for x in ends]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_get_sprite_screen_xy');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[f'memory{x}'] for x in range(6))));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,6),constraints=alias_constraints(i)+tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('sprite_screen_xy');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'GetSpriteScreenXY');assert linked_bytes(ROM,l,28)==bytes.fromhex('1c1c1ae0921c1c1ae0913e04835ff092c604e6f0121cf091e6f012c9')
