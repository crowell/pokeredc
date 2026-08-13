from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AddRegister,Sm83DecRegister,Sm83LoadAHighImmediate,Sm83StoreAHighImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff;CONT=0xeffc;FINISH=0xeffd;DONE=0xeffe;BASE=0xff8b;AUTO=0xffba
KEYS=('base_tile','auto_transfer','fetched','written','saved_b','saved_c','saved_h','saved_l','original_h','original_l')
class Save(angr.SimProcedure):
 def __init__(self,n,kind):super().__init__();self.n=n;self.kind=kind
 def run(self):
  if self.kind=='original':self.state.globals['original_h']=self.state.regs.h;self.state.globals['original_l']=self.state.regs.l
  elif self.kind=='bc':self.state.globals['saved_b']=self.state.regs.b;self.state.globals['saved_c']=self.state.regs.c
  else:self.state.globals['saved_h']=self.state.regs.h;self.state.globals['saved_l']=self.state.regs.l
  self.jump(self.n)  # type: ignore[override]
class Restore(angr.SimProcedure):
 def __init__(self,n,kind):super().__init__();self.n=n;self.kind=kind
 def run(self):
  if self.kind=='bc':self.state.regs.b=self.state.globals['saved_b'];self.state.regs.c=self.state.globals['saved_c']
  else:self.state.regs.h=self.state.globals[self.kind+'_h'];self.state.regs.l=self.state.globals[self.kind+'_l']
  self.jump(self.n)  # type: ignore[override]
class RestoreBcSaveHl(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  self.state.globals['saved_h']=self.state.regs.h;self.state.globals['saved_l']=self.state.regs.l;self.state.regs.b=self.state.globals['saved_b'];self.state.regs.c=self.state.globals['saved_c'];self.jump(self.n)  # type: ignore[override]
class Bound(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)  # type: ignore[override]
class Fetch(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=self.state.globals['fetched'];self.jump(self.n)  # type: ignore[override]
class StartFetch(Fetch):
 def run(self):
  if self.state.globals.get('entered',False):self.jump(CONT);return
  self.state.globals['entered']=True;super().run()
class IncDe(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.de=self.state.regs.de+1;self.jump(self.n)  # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  de_before=self.state.regs.de-1;hl=self.state.regs.hl;self.state.globals['written']=self.state.regs.a;self.state.globals['fetched']=claripy.If(de_before==hl,self.state.regs.a,self.state.globals['fetched']);self.state.regs.hl=hl+1;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 return i
def project():
 l=symbol_location(SYMBOLS,'CopyTileIDs');return l,angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
def setup(s,i):
 set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
 s.memory.store(BASE,i['base_tile']);s.memory.store(AUTO,i['auto_transfer'])
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
def memory(x):return claripy.Concat(x.memory.load(BASE,1),x.memory.load(AUTO,1),*(x.globals[k] for k in KEYS[2:]))
def endpoint(x,result=0):return E(**assembly_registers(x),memory=memory(x),result=claripy.BVV(result,8),constraints=tuple(x.solver.constraints))
def begin(i):
 l,p=project();q=l.address;p.hook(q,Save(q+1,'original'),length=1);p.hook(q+1,Save(q+2,'bc'),length=1);p.hook(q+2,Save(q+3,'saved'),length=1);p.hook(q+3,Sm83LoadAHighImmediate(0x8b,q+5),length=2);p.hook(q+6,Bound(DONE),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=DONE);return [endpoint(m.found[0])]
def byte(i):
 l,p=project();q=l.address;p.hook(q+6,StartFetch(q+7),length=1);p.hook(q+7,Sm83AddRegister('b',q+8),length=1);p.hook(q+8,IncDe(q+9),length=1);p.hook(q+9,Store(q+10),length=1);p.hook(q+10,Sm83DecRegister('c',q+11),length=1);p.hook(q+13,Bound(FINISH),length=1);s=p.factory.blank_state(addr=q+6);setup(s,i);m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {CONT,FINISH})
  if m.active:m.step()
 return [endpoint(x,1 if x.addr==FINISH else 0) for x in m.found]
def row(i):
 l,p=project();q=l.address;p.hook(q+13,Restore(q+14,'saved'),length=1);p.hook(q+17,Sm83AddHlRegisterPair('bc',q+18),length=1);p.hook(q+18,RestoreBcSaveHl(q+19),length=1);p.hook(q+19,Sm83DecRegister('b',q+20),length=1);p.hook(q+1,Save(q+2,'bc'),length=1);p.hook(q+2,Save(q+3,'saved'),length=1);p.hook(q+3,Sm83LoadAHighImmediate(0x8b,q+5),length=2);p.hook(q+6,Bound(CONT),length=1);p.hook(q+22,Bound(FINISH),length=1);s=p.factory.blank_state(addr=q+13);setup(s,i);m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {CONT,FINISH})
  if m.active:m.step()
 return [endpoint(x,1 if x.addr==FINISH else 0) for x in m.found]
def finish(i):
 l,p=project();q=l.address;p.hook(q+24,Sm83StoreAHighImmediate(0xba,q+26),length=2);p.hook(q+26,Restore(q+27,'original'),length=1);s=p.factory.blank_state(addr=q+22);setup(s,i);return [endpoint(x) for x in collect_returns(p,s,RETURN)]
def native(symbol,i,returns=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(symbol);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),result=x.regs.rax[7:0] if returns else claripy.BVV(0,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('part,asm,symbol,returns',(('begin',begin,'port_copy_tile_ids_begin',False),('byte',byte,'port_copy_tile_ids_byte',True),('row',row,'port_copy_tile_ids_row',True),('finish',finish,'port_copy_tile_ids_finish',False)))
def test_equivalence(part,asm,symbol,returns):
 i=inputs('copy_tile_ids_'+part);assert_pathwise_equivalent(asm(i),native(symbol,i,returns),(*REGISTERS,'memory','result'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'CopyTileIDs');assert linked_bytes(ROM,l,28)==bytes.fromhex('e5c5e5f08b471a8013220d20f9e101140009c10520eb3e01e0bae1c9')
