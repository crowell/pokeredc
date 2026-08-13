from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddRegister,Sm83AndImmediate,Sm83CpImmediate,Sm83DecRegister,Sm83IncRegister,Sm83OrRegister,Sm83SlaRegister,Sm83SrlRegister,Sm83XorImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff
CASES=(('FlagAction','port_flag_action',60,'e5d5c57957e6075f7acb3fcb3fcb3f856f3001241c16011d2804cb2218f978a7280afe02280e467ab077180b467aeeffa0771803467aa0c1d1e14fc9'),('ToggleableObjectFlagAction','port_toggleable_object_flag_action',63,'e5d5c57957e6075f7acb3fcb3fcb3f856f3001241c16011d2804cb2218f978a7280bfe0228107e477ab077180d7e477aeeffa07718047e477aa0c1d1e14fc9'))
class Save(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  for r in ('b','c','d','e','h','l'):self.state.globals['saved_'+r]=getattr(self.state.regs,r)
  self.jump(self.n)  # type: ignore[override]
class Restore(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  for r in ('b','c','d','e','h','l'):setattr(self.state.regs,r,self.state.globals['saved_'+r])
  self.jump(self.n)  # type: ignore[override]
class Load(angr.SimProcedure):
 def __init__(self,n,to_b=False):super().__init__();self.n=n;self.to_b=to_b
 def run(self):
  if self.to_b:self.state.regs.b=self.state.globals['value']
  else:self.state.regs.a=self.state.globals['value']
  self.jump(self.n)  # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['value']=self.state.regs.a;self.jump(self.n)  # type: ignore[override]
class AndRegister(angr.SimProcedure):
 def __init__(self,r,n):super().__init__();self.r=r;self.n=n
 def run(self):
  self.state.regs.a=self.state.regs.a&getattr(self.state.regs,self.r);self.state.regs.f=claripy.BVV(0x10,8)|claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8));self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;value:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p);i['value']=claripy.BVS(p+'_value',8);return i
def assembly(symbol,i):
 l=symbol_location(SYMBOLS,symbol);p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;toggle=symbol.startswith('Toggle');p.hook(q,Save(q+3),length=3);p.hook(q+5,Sm83AndImmediate(7,q+7),length=2)
 for o in (9,11,13):p.hook(q+o,Sm83SrlRegister('a',q+o+2),length=2)
 p.hook(q+15,Sm83AddRegister('l',q+16),length=1);p.hook(q+19,Sm83IncRegister('h',q+20),length=1);p.hook(q+20,Sm83IncRegister('e',q+21),length=1);p.hook(q+23,Sm83DecRegister('e',q+24),length=1);p.hook(q+26,Sm83SlaRegister('d',q+28),length=2);p.hook(q+31,Sm83AndImmediate(0xff,q+32),length=1);p.hook(q+34,Sm83CpImmediate(2,q+36),length=2)
 if toggle:
  for o in (38,45,54):p.hook(q+o,Load(q+o+1),length=1)
  for o in (42,51):p.hook(q+o,Store(q+o+1),length=1)
  p.hook(q+41,Sm83OrRegister('b',q+42),length=1);p.hook(q+48,Sm83XorImmediate(0xff,q+50),length=2);p.hook(q+50,AndRegister('b',q+51),length=1);p.hook(q+57,AndRegister('b',q+58),length=1);p.hook(q+58,Restore(q+61),length=3)
 else:
  for o in (38,44,52):p.hook(q+o,Load(q+o+1,True),length=1)
  for o in (41,49):p.hook(q+o,Store(q+o+1),length=1)
  p.hook(q+40,Sm83OrRegister('b',q+41),length=1);p.hook(q+46,Sm83XorImmediate(0xff,q+48),length=2);p.hook(q+48,AndRegister('b',q+49),length=1);p.hook(q+54,AndRegister('b',q+55),length=1);p.hook(q+55,Restore(q+58),length=3)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.globals['value']=i['value'];s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');ends=collect_returns(p,s,RETURN)
 return [E(**assembly_registers(x),value=x.globals['value'],constraints=tuple(x.solver.constraints)) for x in ends]
def native(symbol,i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(symbol);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i['value']);m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),value=x.memory.load(NATIVE_STATE+8,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('symbol,c_symbol,_size,_body',CASES)
def test_equivalence(symbol,c_symbol,_size,_body):
 i=inputs(symbol.lower());assert_pathwise_equivalent(assembly(symbol,i),native(c_symbol,i),(*REGISTERS,'value'))
@pytest.mark.parametrize('symbol,_c_symbol,size,body',CASES)
def test_exact_body(symbol,_c_symbol,size,body):assert linked_bytes(ROM,symbol_location(SYMBOLS,symbol),size)==bytes.fromhex(body)
