from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83CpRegister,Sm83StoreAHighImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff;CONT=0xeffd;READY=0xeffe;SCX=0xff43;KEYS=('stat','scx','fetched_offset','fetched_next')
class StartLoad(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(CONT);return
  self.state.globals['entered']=True;self.state.regs.a=self.state.globals['stat'];self.jump(self.n)  # type: ignore[override]
class Bound(angr.SimProcedure):
 def run(self):self.jump(READY)  # type: ignore[override]
class Fetch(angr.SimProcedure):
 def __init__(self,n,key):super().__init__();self.n=n;self.key=key
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)  # type: ignore[override]
class IncHl(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 return i
def project():
 l=symbol_location(SYMBOLS,'WavyScreen_SetSCX');return l,angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
def setup(s,i):
 set_assembly_registers(s,i);s.memory.store(SCX,i['scx'])
 for k in KEYS:s.globals[k]=i[k]
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
def endpoint(x,i,result):return E(**assembly_registers(x),memory=claripy.Concat(i['stat'],x.memory.load(SCX,1),i['fetched_offset'],i['fetched_next']),result=claripy.BVV(result,8),constraints=tuple(x.solver.constraints))
def poll(i):
 l,p=project();q=l.address;p.hook(q,StartLoad(q+2),length=2);p.hook(q+2,Sm83AndImmediate(3,q+4),length=2);p.hook(q+6,Bound(),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {CONT,READY})
  if m.active:m.step()
 return [endpoint(x,i,1 if x.addr==READY else 0) for x in m.found]
def finish(i):
 l,p=project();q=l.address;p.hook(q+6,Fetch(q+7,'fetched_offset'),length=1);p.hook(q+7,Sm83StoreAHighImmediate(0x43,q+9),length=2);p.hook(q+9,IncHl(q+10),length=1);p.hook(q+10,Fetch(q+11,'fetched_next'),length=1);p.hook(q+11,Sm83CpRegister('d',q+12),length=1);s=p.factory.blank_state(addr=q+6);setup(s,i);return [endpoint(x,i,0) for x in collect_returns(p,s,RETURN)]
def native(symbol,i,returns):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(symbol);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),result=x.regs.rax[7:0] if returns else claripy.BVV(0,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('part,asm,symbol,returns',(('poll',poll,'port_wavy_screen_set_scx_poll',True),('finish',finish,'port_wavy_screen_set_scx_finish',False)))
def test_equivalence(part,asm,symbol,returns):
 i=inputs('wavy_'+part);assert_pathwise_equivalent(asm(i),native(symbol,i,returns),(*REGISTERS,'memory','result'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'WavyScreen_SetSCX');assert linked_bytes(ROM,l,17)==bytes.fromhex('f041e60320fa7ee043237ebac021bf56c9')
