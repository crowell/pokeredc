from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddImmediate,Sm83DecRegister,Sm83IncRegister,Sm83LoadAImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;LOOP=0xeffe;DONE=0xefff;BASE_Y=0xd082;BASE_X=0xd081
KEYS=('base_y','base_x','written_y','written_x','written_tile','written_attributes','saved_b','saved_c')
class Bound(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)  # type: ignore[override]
class StartInner(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):  # type: ignore[override]
  if self.state.globals.get('entered',False):self.jump(LOOP);return
  self.state.globals['entered']=True;self.state.regs.a=self.state.regs.e;self.jump(self.n)
class Store(angr.SimProcedure):
 def __init__(self,n,key):super().__init__();self.n=n;self.key=key
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
class RestoreBC(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.b=self.state.globals['saved_b'];self.state.regs.c=self.state.globals['saved_c'];self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in KEYS:i[n]=claripy.BVS(f'{p}_{n}',8)
 return i
def project():
 l=symbol_location(SYMBOLS,'InitIntroNidorinoOAM');return l,angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
def setup(s,i):
 set_assembly_registers(s,i);s.memory.store(BASE_Y,i['base_y']);s.memory.store(BASE_X,i['base_x'])
 for k in KEYS[2:]:s.globals[k]=i[k]
def memory(x,i):return claripy.Concat(x.memory.load(BASE_Y,1),x.memory.load(BASE_X,1),*(x.globals.get(k,i[k]) for k in KEYS[2:]))
def ep(x,i,result=0):return E(**assembly_registers(x),memory=memory(x,i),result=claripy.BVV(result,8),constraints=tuple(x.solver.constraints))
def begin(i):
 l,p=project();p.hook(l.address+5,Bound(DONE),length=1);s=p.factory.blank_state(addr=l.address);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=DONE);return [ep(m.found[0],i)]
def row_begin(i):
 l,p=project();p.hook(l.address+6,Sm83LoadAImmediate(BASE_Y,l.address+9),length=3);p.hook(l.address+10,Bound(DONE),length=1);s=p.factory.blank_state(addr=l.address+6);setup(s,i);s.globals['saved_b']=i['b'];s.globals['saved_c']=i['c'];m=p.factory.simulation_manager(s);m.explore(find=DONE);return [ep(m.found[0],i)]
def inner(i):
 l,p=project();q=l.address+10;p.hook(q,StartInner(q+1),length=1);p.hook(q+1,Sm83AddImmediate(8,q+3),length=2);p.hook(q+4,Store(q+5,'written_y'),length=1);p.hook(q+5,Sm83LoadAImmediate(BASE_X,q+8),length=3);p.hook(q+8,Store(q+9,'written_x'),length=1);p.hook(q+10,Store(q+11,'written_tile'),length=1);p.hook(q+13,Store(q+14,'written_attributes'),length=1);p.hook(q+14,Sm83IncRegister('d',q+15),length=1);p.hook(q+15,Sm83DecRegister('c',q+16),length=1);p.hook(q+18,Bound(DONE),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {LOOP,DONE})
  if m.active:m.step()
 return [ep(x,i,1 if x.addr==DONE else 0) for x in m.found]
def row_finish(i):
 l,p=project();q=l.address+28;p.hook(q,Sm83LoadAImmediate(BASE_X,q+3),length=3);p.hook(q+3,Sm83AddImmediate(8,q+5),length=2);p.hook(q+5,Sm83StoreAImmediate(BASE_X,q+8),length=3);p.hook(q+8,RestoreBC(q+9),length=1);p.hook(q+9,Sm83DecRegister('b',q+10),length=1);p.hook(l.address+5,Bound(LOOP),length=1);p.hook(q+12,Bound(DONE),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {LOOP,DONE})
  if m.active:m.step()
 return [ep(x,i,1 if x.addr==DONE else 0) for x in m.found]
def native(sym,i,returns=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,8),result=x.regs.rax[7:0] if returns else claripy.BVV(0,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('part,asm,c,ret',[('begin',begin,'port_init_intro_nidorino_oam_begin',False),('row_begin',row_begin,'port_init_intro_nidorino_oam_row_begin',False),('inner',inner,'port_init_intro_nidorino_oam_inner_step',True),('row_finish',row_finish,'port_init_intro_nidorino_oam_row_finish',True)])
def test_equivalence(part,asm,c,ret):
 i=inputs('init_intro_'+part);assert_pathwise_equivalent(asm(i),native(c,i,ret),(*REGISTERS,'memory','result'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'InitIntroNidorinoOAM');assert linked_bytes(ROM,l,41)==bytes.fromhex('2100c31600c5fa82d05f7bc6085f22fa81d0227a223e8022140d20eefa81d0c608ea81d0c10520ddc9')
