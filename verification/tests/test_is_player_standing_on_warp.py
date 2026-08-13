from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83DecRegister,Sm83SetAtHl,Sm83StoreAHighImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff;CONT=0xeffe;BEGIN_DONE=0xeffd
COUNT=0xd3ae;Y=0xd361;X=0xd362;DEST_WARP=0xd42f;DEST_MAP=0xff8b;FLAGS=0xd736
KEYS=('number_of_warps','y','x','destination_warp','destination_map','movement_flags','fetched_y','fetched_x','fetched_warp','fetched_map')
class Fetch(angr.SimProcedure):
 def __init__(self,n,key,inc=False):super().__init__();self.n=n;self.key=key;self.inc=inc
 def run(self):self.state.regs.a=self.state.globals[self.key];self.state.regs.hl=self.state.regs.hl+(1 if self.inc else 0);self.jump(self.n)  # type: ignore[override]
class CpFetched(angr.SimProcedure):
 def __init__(self,n,key):super().__init__();self.n=n;self.key=key
 def run(self):
  a=self.state.regs.a;b=self.state.globals[self.key];self.state.regs.f=claripy.BVV(2,8)|claripy.If(a==b,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If((a&15).ULT(b&15),claripy.BVV(0x10,8),claripy.BVV(0,8))|claripy.If(a.ULT(b),claripy.BVV(1,8),claripy.BVV(0,8));self.jump(self.n)  # type: ignore[override]
class StartFetch(Fetch):
 def run(self):
  if self.state.globals.get('entered',False):self.jump(CONT);return
  self.state.globals['entered']=True;super().run()
class IncHl(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
class Bound(angr.SimProcedure):
 def run(self):self.jump(BEGIN_DONE)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 return i
def project():
 l=symbol_location(SYMBOLS,'IsPlayerStandingOnWarp');return l,angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
def setup(s,i):
 set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
 for a,k in ((COUNT,'number_of_warps'),(Y,'y'),(X,'x'),(DEST_WARP,'destination_warp'),(DEST_MAP,'destination_map'),(FLAGS,'movement_flags')):s.memory.store(a,i[k])
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
def memory(x,i):return claripy.Concat(x.memory.load(COUNT,1),x.memory.load(Y,1),x.memory.load(X,1),x.memory.load(DEST_WARP,1),x.memory.load(DEST_MAP,1),x.memory.load(FLAGS,1),*(i[k] for k in KEYS[6:]))
def endpoint(x,i,result):return E(**assembly_registers(x),memory=memory(x,i),result=claripy.BVV(result,8),constraints=tuple(x.solver.constraints))
def begin(i):
 l,p=project();q=l.address;p.hook(q,Fetch(q+3,'number_of_warps'),length=3);p.hook(q+3,Sm83AndImmediate(0xff,q+4),length=1);p.hook(q+9,Bound(),length=3);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {BEGIN_DONE,RETURN})
  if m.active:m.step()
 return [endpoint(x,i,1 if x.addr==RETURN else 0) for x in m.found]
def step(i):
 l,p=project();q=l.address;p.hook(q+9,StartFetch(q+12,'y'),length=3);p.hook(q+12,CpFetched(q+13,'fetched_y'),length=1);p.hook(q+15,IncHl(q+16),length=1);p.hook(q+16,Fetch(q+19,'x'),length=3);p.hook(q+19,CpFetched(q+20,'fetched_x'),length=1);p.hook(q+22,IncHl(q+23),length=1);p.hook(q+23,Fetch(q+24,'fetched_warp',True),length=1);p.hook(q+24,Sm83StoreAImmediate(DEST_WARP,q+27),length=3);p.hook(q+27,Fetch(q+28,'fetched_map'),length=1);p.hook(q+28,Sm83StoreAHighImmediate(0x8b,q+30),length=2);p.hook(q+33,Sm83SetAtHl(2,q+35),length=2)
 for o in (36,37,38,39):p.hook(q+o,IncHl(q+o+1),length=1)
 p.hook(q+40,Sm83DecRegister('c',q+41),length=1);s=p.factory.blank_state(addr=q+9);setup(s,i);m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {CONT,RETURN})
  if m.active:m.step()
 return [endpoint(x,i,0 if x.addr==CONT else 1) for x in m.found]
def native(symbol,i,returns=True):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(symbol);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),result=x.regs.rax[7:0] if returns else claripy.BVV(0,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('part,asm',(('begin',begin),('step',step)))
def test_equivalence(part,asm):
 i=inputs('standing_warp_'+part);assert_pathwise_equivalent(asm(i),native('port_is_player_standing_on_warp_'+part,i),(*REGISTERS,'memory','result'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'IsPlayerStandingOnWarp');assert linked_bytes(ROM,l,44)==bytes.fromhex('faaed3a7c84f21afd3fa61d3be201523fa62d3be200f232aea2fd47ee08b2136d7cbd6c9232323230d20dec9')
