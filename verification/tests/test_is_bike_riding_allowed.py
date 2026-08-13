from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83CpImmediate,Sm83CpRegister,Sm83IncRegister,Sm83LoadAImmediate,Sm83Scf
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;CONT=0xeffc;SCAN=0xeffd;ALLOWED=0xeffe;DENIED=0xefff;MAP=0xd35e;TILESET=0xd367
KEYS=('current_map','current_tileset','fetched')
class Bound(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)  # type: ignore[override]
class StartFetch(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(CONT);return
  self.state.globals['entered']=True;self.state.regs.a=self.state.globals['fetched'];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in KEYS:i[n]=claripy.BVS(f'{p}_{n}',8)
 return i
def project():
 l=symbol_location(SYMBOLS,'IsBikeRidingAllowed');return l,angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
def setup(s,i):set_assembly_registers(s,i);s.memory.store(MAP,i['current_map']);s.memory.store(TILESET,i['current_tileset']);s.globals['fetched']=i['fetched']
def mem(x,i):return claripy.Concat(x.memory.load(MAP,1),x.memory.load(TILESET,1),i['fetched'])
def ep(x,i,r):return E(**assembly_registers(x),memory=mem(x,i),result=claripy.BVV(r,8),constraints=tuple(x.solver.constraints))
def begin(i):
 l,p=project();q=l.address;p.hook(q,Sm83LoadAImmediate(MAP,q+3),length=3);p.hook(q+3,Sm83CpImmediate(0x22,q+5),length=2);p.hook(q+7,Sm83CpImmediate(0x09,q+9),length=2);p.hook(q+11,Sm83LoadAImmediate(TILESET,q+14),length=3);p.hook(q+18,Bound(SCAN),length=1);p.hook(q+27,Sm83Scf(ALLOWED),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=lambda x:x.addr in {SCAN,ALLOWED},num_find=3);return [ep(x,i,1 if x.addr==ALLOWED else 0) for x in m.found]
def step(i):
 l,p=project();q=l.address+18;p.hook(q,StartFetch(q+1),length=1);p.hook(q+1,Sm83CpRegister('b',q+2),length=1);p.hook(q+4,Sm83IncRegister('a',q+5),length=1);p.hook(q+7,Sm83AndImmediate(0xff,q+8),length=1);p.hook(q+8,Bound(DENIED),length=1);p.hook(l.address+27,Sm83Scf(ALLOWED),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {CONT,ALLOWED,DENIED})
  if m.active:m.step()
 code={CONT:0,ALLOWED:1,DENIED:2};return [ep(x,i,code[x.addr]) for x in m.found]
def native(sym,i,returns=True):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,3),result=x.regs.rax[7:0] if returns else claripy.BVV(0,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('part,asm,c',[('begin',begin,'port_is_bike_riding_allowed_begin'),('step',step,'port_is_bike_riding_allowed_step')])
def test_equivalence(part,asm,c):
 i=inputs('bike_'+part);assert_pathwise_equivalent(asm(i),native(c,i),(*REGISTERS,'memory','result'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'IsBikeRidingAllowed');assert linked_bytes(ROM,l,29)==bytes.fromhex('fa5ed3fe222814fe092810fa67d34721e2092ab828053c20f9a7c937c9')
