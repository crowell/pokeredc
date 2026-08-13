from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83CpRegister,Sm83StoreAHighImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff;CONT=0xeffc;READY=0xeffd;DONE=0xeffe;SCX=0xff43;KEYS=('ly','scx')
class StartLoad(angr.SimProcedure):
 def __init__(self,n,reentry):super().__init__();self.n=n;self.reentry=reentry
 def run(self):
  if self.state.globals.get('entered',False):self.jump(self.reentry);return
  self.state.globals['entered']=True;self.state.regs.a=self.state.globals['ly'];self.jump(self.n)  # type: ignore[override]
class Bound(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 return i
def project(symbol):
 l=symbol_location(SYMBOLS,symbol);return l,angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
def setup(s,i):set_assembly_registers(s,i);s.globals['ly']=i['ly'];s.memory.store(SCX,i['scx']);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
def endpoint(x,i,result):return E(**assembly_registers(x),memory=claripy.Concat(i['ly'],x.memory.load(SCX,1)),result=claripy.BVV(result,8),constraints=tuple(x.solver.constraints))
def assembly(symbol,part,i):
 l,p=project(symbol);q=l.address
 if part=='wait_l':
  p.hook(q,StartLoad(q+2,CONT),length=2);p.hook(q+2,Sm83CpRegister('l',q+3),length=1);p.hook(q+5,Bound(READY),length=1);start=q;targets={CONT,READY}
 elif part=='store':
  p.hook(q+6,Sm83StoreAHighImmediate(0x43,DONE),length=2);start=q+5;targets={DONE}
 else:
  p.hook(q+8,StartLoad(q+10,CONT),length=2);p.hook(q+10,Sm83CpRegister('h',q+11),length=1);start=q+8;targets={CONT,RETURN}
 s=p.factory.blank_state(addr=start);setup(s,i);m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in targets)
  if m.active:m.step()
 return [endpoint(x,i,1 if (part=='wait_l' and x.addr==READY) or (part=='wait_h' and x.addr==RETURN) else 0) for x in m.found]
def native(symbol,i,returns):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(symbol);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),result=x.regs.rax[7:0] if returns else claripy.BVV(0,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('routine',('SetScrollXForSlidingPlayerBodyLeft','ScrollCreditsMonLeft_SetSCX','ScrollTitleScreenGameVersion'))
@pytest.mark.parametrize('part,c_symbol,returns',(('wait_l','port_scanline_scx_wait_for_l',True),('store','port_scanline_scx_store_h',False),('wait_h','port_scanline_scx_wait_until_not_h',True)))
def test_equivalence(routine,part,c_symbol,returns):
 i=inputs(routine+'_'+part);assert_pathwise_equivalent(assembly(routine,part,i),native(c_symbol,i,returns),(*REGISTERS,'memory','result'))
@pytest.mark.parametrize('routine',('SetScrollXForSlidingPlayerBodyLeft','ScrollCreditsMonLeft_SetSCX','ScrollTitleScreenGameVersion'))
def test_exact_body(routine):
 l=symbol_location(SYMBOLS,routine);assert linked_bytes(ROM,l,14)==bytes.fromhex('f044bd20fb7ce043f044bc28fbc9')
