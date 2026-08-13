from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83DecRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff;CONT=0xeffc;FINISH=0xeffd;DONE=0xeffe;KEYS=('fetched','written')
class Bound(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)  # type: ignore[override]
class StartFetch(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(CONT);return
  self.state.globals['entered']=True;self.state.regs.a=self.state.globals['fetched'];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['written']=self.state.regs.a;self.jump(self.n)  # type: ignore[override]
class IncDe(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.de=self.state.regs.de+1;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 return i
def project():
 l=symbol_location(SYMBOLS,'TwoOptionMenu_SaveScreenTiles');return l,angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
def setup(s,i):set_assembly_registers(s,i);s.globals['fetched']=i['fetched'];s.globals['written']=i['written'];s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
def endpoint(x,result):return E(**assembly_registers(x),memory=claripy.Concat(x.globals['fetched'],x.globals['written']),result=claripy.BVV(result,8),constraints=tuple(x.solver.constraints))
def begin(i):
 l,p=project();q=l.address;p.hook(q+6,Bound(DONE),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=DONE);return [endpoint(m.found[0],0)]
def byte(i):
 l,p=project();q=l.address;p.hook(q+6,StartFetch(q+7),length=1);p.hook(q+7,Store(q+8),length=1);p.hook(q+8,IncDe(q+9),length=1);p.hook(q+9,Sm83DecRegister('c',q+10),length=1);p.hook(q+12,Bound(FINISH),length=1);s=p.factory.blank_state(addr=q+6);setup(s,i);m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {CONT,FINISH})
  if m.active:m.step()
 return [endpoint(x,1 if x.addr==FINISH else 0) for x in m.found]
def row(i):
 l,p=project();q=l.address;p.hook(q+16,Sm83AddHlRegisterPair('bc',q+17),length=1);p.hook(q+20,Sm83DecRegister('b',q+21),length=1);p.hook(q+6,Bound(CONT),length=1);s=p.factory.blank_state(addr=q+12);setup(s,i);m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {CONT,RETURN})
  if m.active:m.step()
 return [endpoint(x,1 if x.addr==RETURN else 0) for x in m.found]
def native(symbol,i,returns):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(symbol);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),result=x.regs.rax[7:0] if returns else claripy.BVV(0,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('part,asm,symbol,returns',(('begin',begin,'port_two_option_menu_save_screen_tiles_begin',False),('byte',byte,'port_two_option_menu_save_screen_tiles_byte',True),('row',row,'port_two_option_menu_save_screen_tiles_row',True)))
def test_equivalence(part,asm,symbol,returns):
 i=inputs('menu_save_'+part);assert_pathwise_equivalent(asm(i),native(symbol,i,returns),(*REGISTERS,'memory','result'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'TwoOptionMenu_SaveScreenTiles');assert linked_bytes(ROM,l,24)==bytes.fromhex('11e9ce0106052a12130d20fac5010e0009c10e060520efc9')
