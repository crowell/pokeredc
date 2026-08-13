from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83CpImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;LOOP=0xeffc;READ=0xeffd;DONE=0xefff
KEYS=('fetched_compare','fetched_coordinate','fetched_name_low','fetched_name_high','written')
class Bound(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)  # type: ignore[override]
class StartCp(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(LOOP);return
  self.state.globals['entered']=True;x=self.state.regs.a;y=self.state.globals['fetched_compare'];self.state.regs.f=claripy.BVV(2,8)|claripy.If(x==y,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If((x&15).ULT(y&15),claripy.BVV(0x10,8),claripy.BVV(0,8))|claripy.If(x.ULT(y),claripy.BVV(1,8),claripy.BVV(0,8));self.jump(self.n)  # type: ignore[override]
class Fetch(angr.SimProcedure):
 def __init__(self,n,key,inc=True):super().__init__();self.n=n;self.key=key;self.inc=inc
 def run(self):self.state.regs.a=self.state.globals[self.key];self.state.regs.hl=self.state.regs.hl+(1 if self.inc else 0);self.jump(self.n)  # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['written']=self.state.regs.a;self.jump(self.n)  # type: ignore[override]
class LoadH(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.h=self.state.globals['fetched_name_high'];self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in KEYS:i[n]=claripy.BVS(f'{p}_{n}',8)
 return i
def project():
 l=symbol_location(SYMBOLS,'LoadTownMapEntry');return l,angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
def setup(s,i):
 set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
def mem(x,i):return claripy.Concat(i['fetched_compare'],i['fetched_coordinate'],i['fetched_name_low'],i['fetched_name_high'],x.globals.get('written',i['written']))
def ep(x,i,r=0):return E(**assembly_registers(x),memory=mem(x,i),result=claripy.BVV(r,8),constraints=tuple(x.solver.constraints))
def begin(i):
 l,p=project();q=l.address;p.hook(q,Sm83CpImmediate(0x25,q+2),length=2);p.hook(q+10,Bound(LOOP),length=1);p.hook(q+25,Sm83AddHlRegisterPair('bc',q+26),length=1);p.hook(q+26,Sm83AddHlRegisterPair('bc',q+27),length=1);p.hook(q+27,Sm83AddHlRegisterPair('bc',q+28),length=1);p.hook(q+28,Bound(READ),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=lambda x:x.addr in {LOOP,READ},num_find=2);return [ep(x,i,1 if x.addr==READ else 0) for x in m.found]
def scan(i):
 l,p=project();q=l.address+10;p.hook(q,StartCp(q+1),length=1);p.hook(q+3,Sm83AddHlRegisterPair('bc',q+4),length=1);p.hook(l.address+17,Bound(READ),length=2);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {LOOP,READ})
  if m.active:m.step()
 return [ep(x,i,1 if x.addr==READ else 0) for x in m.found]
def finish(i):
 l,p=project();q=l.address+28;p.hook(q,Fetch(q+1,'fetched_coordinate'),length=1);p.hook(q+1,Store(q+2),length=1);p.hook(q+2,Fetch(q+3,'fetched_name_low'),length=1);p.hook(q+3,LoadH(q+4),length=1);p.hook(q+5,Bound(DONE),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=DONE);return [ep(m.found[0],i)]
def native(sym,i,returns=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,5),result=x.regs.rax[7:0] if returns else claripy.BVV(0,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('part,asm,c,ret',[('begin',begin,'port_load_town_map_entry_begin',True),('scan',scan,'port_load_town_map_entry_scan_step',True),('finish',finish,'port_load_town_map_entry_finish',False)])
def test_equivalence(part,asm,c,ret):
 i=inputs('town_entry_'+part);assert_pathwise_equivalent(asm(i),native(c,i,ret),(*REGISTERS,'memory','result'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'LoadTownMapEntry');assert linked_bytes(ROM,l,34)==bytes.fromhex('fe25380f010400218253be38030918fa2318092113534f06000909092a122a666fc9')
