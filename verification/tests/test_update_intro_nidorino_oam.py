from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83DecRegister,Sm83IncRegister,Sm83LoadAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;LOOP=0xeffe;DONE=0xefff;BASE_TILE=0xd09f;BASE_Y=0xd082;BASE_X=0xd081
class Bound(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)  # type: ignore[override]
class StartLoad(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):  # type: ignore[override]
  if self.state.globals.get('entered',False):self.jump(LOOP);return
  self.state.globals['entered']=True;self.state.regs.a=self.state.memory.load(BASE_Y,1);self.jump(self.n)
class AddCurrent(angr.SimProcedure):
 def __init__(self,n,key):super().__init__();self.n=n;self.key=key
 def run(self):  # type: ignore[override]
  x=self.state.regs.a;y=self.state.globals[self.key];w=claripy.ZeroExt(1,x)+claripy.ZeroExt(1,y);r=w[7:0];self.state.regs.a=r;self.state.regs.f=claripy.If(r==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If((x&15)+(y&15)>15,claripy.BVV(0x10,8),claripy.BVV(0,8))|claripy.ZeroExt(7,w[8]);self.jump(self.n)
class Store(angr.SimProcedure):
 def __init__(self,n,key,inc=True):super().__init__();self.n=n;self.key=key;self.inc=inc
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.state.regs.hl=self.state.regs.hl+(1 if self.inc else 0);self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
KEYS=('base_tile','base_y','base_x','fetched_y','fetched_x','written_y','written_x','written_tile')
def inputs(p):
 i=symbolic_registers(p)
 for n in KEYS:i[n]=claripy.BVS(f'{p}_{n}',8)
 return i
def project():
 l=symbol_location(SYMBOLS,'UpdateIntroNidorinoOAM');return l,angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
def mem(x,i):return claripy.Concat(x.memory.load(BASE_TILE,1),x.memory.load(BASE_Y,1),x.memory.load(BASE_X,1),i['fetched_y'],i['fetched_x'],x.globals.get('written_y',i['written_y']),x.globals.get('written_x',i['written_x']),x.globals.get('written_tile',i['written_tile']))
def setup(s,i):
 set_assembly_registers(s,i);s.memory.store(BASE_TILE,i['base_tile']);s.memory.store(BASE_Y,i['base_y']);s.memory.store(BASE_X,i['base_x'])
 for k in KEYS[3:]:s.globals[k]=i[k]
def begin(i):
 l,p=project();p.hook(l.address+3,Sm83LoadAImmediate(BASE_TILE,l.address+6),length=3);p.hook(l.address+7,Bound(DONE),length=3);s=p.factory.blank_state(addr=l.address);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=DONE);x=m.found[0];return [E(**assembly_registers(x),memory=mem(x,i),result=claripy.BVV(0,8),constraints=tuple(x.solver.constraints))]
def step(i):
 l,p=project();q=l.address+7;p.hook(q,StartLoad(q+3),length=3);p.hook(q+3,AddCurrent(q+4,'fetched_y'),length=1);p.hook(q+4,Store(q+5,'written_y'),length=1);p.hook(q+5,Sm83LoadAImmediate(BASE_X,q+8),length=3);p.hook(q+8,AddCurrent(q+9,'fetched_x'),length=1);p.hook(q+9,Store(q+10,'written_x'),length=1);p.hook(q+11,Store(q+12,'written_tile'),length=1);p.hook(q+13,Sm83IncRegister('d',q+14),length=1);p.hook(q+14,Sm83DecRegister('c',q+15),length=1);p.hook(q+17,Bound(DONE),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {LOOP,DONE})
  if m.active:m.step()
 return [E(**assembly_registers(x),memory=mem(x,i),result=claripy.BVV(1 if x.addr==DONE else 0,8),constraints=tuple(x.solver.constraints)) for x in m.found]
def native(sym,i,returns=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,8),result=x.regs.rax[7:0] if returns else claripy.BVV(0,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('part,asm,c,ret',[('begin',begin,'port_update_intro_nidorino_oam_begin',False),('step',step,'port_update_intro_nidorino_oam_step',True)])
def test_equivalence(part,asm,c,ret):
 i=inputs('intro_'+part);assert_pathwise_equivalent(asm(i),native(c,i,ret),(*REGISTERS,'memory','result'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'UpdateIntroNidorinoOAM');assert linked_bytes(ROM,l,25)==bytes.fromhex('2100c3fa9fd057fa82d08622fa81d086227a2223140d20efc9')
