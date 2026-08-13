from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83DecRegister,Sm83LoadAImmediate,Sm83SwapRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;LOOP=0xeffe;DONE=0xefff;DRIFT=0xcd3d
KEYS=('drift','fetched','written','saved_b','saved_c','saved_d','saved_e')
class Bound(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)  # type: ignore[override]
class IncTwice(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):  # type: ignore[override]
  if self.state.globals.get('entered',False):self.jump(LOOP);return
  self.state.globals['entered']=True;x=self.state.globals['fetched'];r=x+2;self.state.globals['written']=r;self.state.regs.f=(self.state.regs.f&1)|claripy.If(r==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If((x+1&15)==15,claripy.BVV(0x10,8),claripy.BVV(0,8));self.jump(self.n)
class Restore(angr.SimProcedure):
 def run(self):  # type: ignore[override]
  for r in ('b','c','d','e'):setattr(self.state.regs,r,self.state.globals['saved_'+r])
  self.jump(DONE)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in KEYS:i[n]=claripy.BVS(f'{p}_{n}',8)
 return i
def project():
 l=symbol_location(SYMBOLS,'VermilionDock_AnimSmokePuffDriftRight');return l,angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
def setup(s,i):
 set_assembly_registers(s,i);s.memory.store(DRIFT,i['drift'])
 for k in KEYS[1:]:s.globals[k]=i[k]
def memory(x,i):return claripy.Concat(x.memory.load(DRIFT,1),i['fetched'],x.globals.get('written',i['written']),*(x.globals.get(k,i[k]) for k in KEYS[3:]))
def begin(i):
 l,p=project();p.hook(l.address+5,Sm83LoadAImmediate(DRIFT,l.address+8),length=3);p.hook(l.address+8,Sm83SwapRegister('a',l.address+10),length=2);p.hook(l.address+14,Bound(DONE),length=1);s=p.factory.blank_state(addr=l.address+2);setup(s,i);s.globals['saved_b']=i['b'];s.globals['saved_c']=i['c'];s.globals['saved_d']=i['d'];s.globals['saved_e']=i['e'];m=p.factory.simulation_manager(s);m.explore(find=DONE);x=m.found[0];return [E(**assembly_registers(x),memory=memory(x,i),result=claripy.BVV(0,8),constraints=tuple(x.solver.constraints))]
def step(i):
 l,p=project();q=l.address+14;p.hook(q,IncTwice(q+2),length=2);p.hook(q+2,Sm83AddHlRegisterPair('de',q+3),length=1);p.hook(q+3,Sm83DecRegister('c',q+4),length=1);p.hook(q+6,Bound(DONE),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {LOOP,DONE})
  if m.active:m.step()
 return [E(**assembly_registers(x),memory=memory(x,i),result=claripy.BVV(1 if x.addr==DONE else 0,8),constraints=tuple(x.solver.constraints)) for x in m.found]
def finish(i):
 l,p=project();p.hook(l.address+20,Restore(),length=3);s=p.factory.blank_state(addr=l.address+20);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=DONE);x=m.found[0];return [E(**assembly_registers(x),memory=memory(x,i),result=claripy.BVV(0,8),constraints=tuple(x.solver.constraints))]
def native(sym,i,returns=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,7),result=x.regs.rax[7:0] if returns else claripy.BVV(0,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('part,asm,c,ret',[('begin',begin,'port_vermilion_dock_smoke_drift_begin',False),('step',step,'port_vermilion_dock_smoke_drift_step',True),('finish',finish,'port_vermilion_dock_smoke_drift_finish',False)])
def test_equivalence(part,asm,c,ret):
 i=inputs('smoke_'+part);assert_pathwise_equivalent(asm(i),native(c,i,ret),(*REGISTERS,'memory','result'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'VermilionDock_AnimSmokePuffDriftRight');assert linked_bytes(ROM,l,23)==bytes.fromhex('c5d52111c3fa3dcdcb374f1104003434190d20fad1c1c9')
