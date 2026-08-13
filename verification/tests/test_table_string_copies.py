from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83CpImmediate,Sm83DecRegister,Sm83LoadAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;CONT=0xeffd;DONE=0xefff
CASES=(('Route23CopyBadgeTextScript','port_route23_copy_badge_text_begin',0xcd3d,False,25,'217652fa3dcd4f060009092a666f116dcd2a1213fe5020f9c9'),('SaveTrainerName','port_save_trainer_name_begin',0xd031,True,26,'21647efa31d03d4f060009092a666f116dcd2a1213fe5020f9c9'))
KEYS=('selector','pointer_low','pointer_high','fetched','written')
class FetchPointer(angr.SimProcedure):
 def __init__(self,n,high=False):super().__init__();self.n=n;self.high=high
 def run(self):
  if self.high:self.state.regs.h=self.state.globals['pointer_high']
  else:self.state.regs.a=self.state.globals['pointer_low'];self.state.regs.hl=self.state.regs.hl+1
  self.jump(self.n)  # type: ignore[override]
class StartFetch(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(CONT);return
  self.state.globals['entered']=True;self.state.regs.a=self.state.globals['fetched'];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['written']=self.state.regs.a;self.jump(self.n)  # type: ignore[override]
class IncDE(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.de=self.state.regs.de+1;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in KEYS:i[n]=claripy.BVS(f'{p}_{n}',8)
 return i
def setup(s,i,selector):
 set_assembly_registers(s,i);s.memory.store(selector,i['selector'])
 for k in KEYS[1:]:s.globals[k]=i[k]
def mem(x,i,selector):return claripy.Concat(x.memory.load(selector,1),i['pointer_low'],i['pointer_high'],i['fetched'],x.globals.get('written',i['written']))
def setup_assembly(symbol,selector,decrement,i):
 l=symbol_location(SYMBOLS,symbol);p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q+3,Sm83LoadAImmediate(selector,q+6),length=3)
 base=7 if decrement else 6
 if decrement:p.hook(q+6,Sm83DecRegister('a',q+7),length=1)
 p.hook(q+base+3,Sm83AddHlRegisterPair('bc',q+base+4),length=1);p.hook(q+base+4,Sm83AddHlRegisterPair('bc',q+base+5),length=1);p.hook(q+base+5,FetchPointer(q+base+6),length=1);p.hook(q+base+6,FetchPointer(q+base+7,True),length=1);p.hook(q+base+11,Bound(),length=1);s=p.factory.blank_state(addr=q);setup(s,i,selector);m=p.factory.simulation_manager(s);m.explore(find=DONE);x=m.found[0];return [E(**assembly_registers(x),memory=mem(x,i,selector),result=claripy.BVV(0,8),constraints=tuple(x.solver.constraints))]
class Bound(angr.SimProcedure):
 def run(self):self.jump(DONE)  # type: ignore[override]
def step_assembly(i):
 l=symbol_location(SYMBOLS,'Route23CopyBadgeTextScript');q=l.address+17;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q});p.hook(q,StartFetch(q+1),length=1);p.hook(q+1,Store(q+2),length=1);p.hook(q+2,IncDE(q+3),length=1);p.hook(q+3,Sm83CpImmediate(0x50,q+5),length=2);p.hook(q+7,Bound(),length=1);s=p.factory.blank_state(addr=q);setup(s,i,0xcd3d);m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {CONT,DONE})
  if m.active:m.step()
 return [E(**assembly_registers(x),memory=mem(x,i,0xcd3d),result=claripy.BVV(1 if x.addr==DONE else 0,8),constraints=tuple(x.solver.constraints)) for x in m.found]
def native(symbol,i,returns=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(symbol);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,5),result=x.regs.rax[7:0] if returns else claripy.BVV(0,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('symbol,c_symbol,selector,decrement,_size,_body',CASES)
def test_setup(symbol,c_symbol,selector,decrement,_size,_body):
 i=inputs(symbol.lower());assert_pathwise_equivalent(setup_assembly(symbol,selector,decrement,i),native(c_symbol,i),(*REGISTERS,'memory','result'))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_step():
 i=inputs('table_string_step');assert_pathwise_equivalent(step_assembly(i),native('port_table_string_copy_step',i,True),(*REGISTERS,'memory','result'))
@pytest.mark.parametrize('symbol,_c_symbol,_selector,_decrement,size,body',CASES)
def test_exact_body(symbol,_c_symbol,_selector,_decrement,size,body):assert linked_bytes(ROM,symbol_location(SYMBOLS,symbol),size)==bytes.fromhex(body)
