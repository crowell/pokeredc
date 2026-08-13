from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate,Sm83CpRegister,Sm83LoadAImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;CONT=0xeffd;FINISH=0xeffe;DONE=0xefff;TILESET=0xd367;COORD_TILE=0xc45c;OUTPUT=0xcd5b
KEYS=('current_tileset','coordinate_tile','standing_value','fetched_tileset','fetched_tile','fetched_value')
class Bound(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)  # type: ignore[override]
class StartFetch(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(CONT);return
  self.state.globals['entered']=True;self.state.regs.a=self.state.globals['fetched_tileset'];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
class FetchB(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.b=self.state.globals['fetched_value'];self.jump(self.n)  # type: ignore[override]
class CpTile(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  a=self.state.regs.a;b=self.state.globals['fetched_tile'];self.state.regs.f=claripy.BVV(2,8)|claripy.If(a==b,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If((a&15).ULT(b&15),claripy.BVV(0x10,8),claripy.BVV(0,8))|claripy.If(a.ULT(b),claripy.BVV(1,8),claripy.BVV(0,8));self.jump(self.n)  # type: ignore[override]
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
 l=symbol_location(SYMBOLS,'IsPlayerStandingOnWarpPadOrHole');return l,angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
def setup(s,i):
 set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
 s.memory.store(TILESET,i['current_tileset']);s.memory.store(COORD_TILE,i['coordinate_tile']);s.memory.store(OUTPUT,i['standing_value'])
def memory(x,i):return claripy.Concat(x.memory.load(TILESET,1),x.memory.load(COORD_TILE,1),x.memory.load(OUTPUT,1),*(i[k] for k in KEYS[3:]))
def endpoint(x,i,result=0):return E(**assembly_registers(x),memory=memory(x,i),result=claripy.BVV(result,8),constraints=tuple(x.solver.constraints))
def begin(i):
 l,p=project();q=l.address;p.hook(q+5,Sm83LoadAImmediate(TILESET,q+8),length=3);p.hook(q+9,Bound(DONE),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=DONE);return [endpoint(m.found[0],i)]
def step(i):
 l,p=project();q=l.address;p.hook(q+9,StartFetch(q+10),length=1);p.hook(q+10,Sm83CpImmediate(0xff,q+12),length=2);p.hook(q+14,Sm83CpRegister('c',q+15),length=1);p.hook(q+17,Sm83LoadAImmediate(COORD_TILE,q+20),length=3);p.hook(q+20,CpTile(q+21),length=1);p.hook(q+23,IncHl(q+24),length=1);p.hook(q+24,IncHl(q+25),length=1);p.hook(q+27,IncHl(q+28),length=1);p.hook(q+28,FetchB(q+29),length=1);p.hook(q+29,Bound(FINISH),length=1);s=p.factory.blank_state(addr=q+9);setup(s,i);m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {CONT,FINISH})
  if m.active:m.step()
 return [endpoint(x,i,1 if x.addr==FINISH else 0) for x in m.found]
def finish(i):
 l,p=project();q=l.address;p.hook(q+30,Sm83StoreAImmediate(OUTPUT,q+33),length=3);p.hook(q+33,Bound(DONE),length=1);s=p.factory.blank_state(addr=q+29);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=DONE);return [endpoint(m.found[0],i)]
def native(symbol,i,returns=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(symbol);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),result=x.regs.rax[7:0] if returns else claripy.BVV(0,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('part,asm,returns',(('begin',begin,False),('step',step,True),('finish',finish,False)))
def test_equivalence(part,asm,returns):
 i=inputs('warp_pad_'+part);assert_pathwise_equivalent(asm(i),native('port_is_player_standing_on_warp_pad_or_hole_'+part,i,returns),(*REGISTERS,'memory','result'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'IsPlayerStandingOnWarpPadOrHole');assert linked_bytes(ROM,l,34)==bytes.fromhex('060021a947fa67d34f2afeff280fb92006fa5cc4be2804232318ee234678ea5bcdc9')
