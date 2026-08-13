from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83CpRegister,Sm83DecRegister,Sm83LoadAImmediate,Sm83ResRegister,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;CONT=0xeffc;FINISH=0xeffd;DONE=0xeffe
TEXT=0xcd3d;ANIM=0xcd3e;STYLE=0xcd3f;OPTIONS=0xd355;KEYS=('text_speed_cursor','battle_animation_cursor','battle_style_cursor','options','fetched_compare','fetched_value')
class Bound(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)  # type: ignore[override]
class StartFetch(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(CONT);return
  self.state.globals['entered']=True;self.state.regs.a=self.state.globals['fetched_compare'];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
class Fetch(angr.SimProcedure):
 def __init__(self,n,key):super().__init__();self.n=n;self.key=key
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)  # type: ignore[override]
class IncHl(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
class SetD(angr.SimProcedure):
 def __init__(self,n,bit):super().__init__();self.n=n;self.bit=bit
 def run(self):self.state.regs.d=self.state.regs.d|(1<<self.bit);self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 return i
def project():
 l=symbol_location(SYMBOLS,'SetOptionsFromCursorPositions');return l,angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
def setup(s,i):
 set_assembly_registers(s,i)
 for a,k in ((TEXT,'text_speed_cursor'),(ANIM,'battle_animation_cursor'),(STYLE,'battle_style_cursor'),(OPTIONS,'options')):s.memory.store(a,i[k])
 for k in KEYS:s.globals[k]=i[k]
def memory(x,i):return claripy.Concat(x.memory.load(TEXT,1),x.memory.load(ANIM,1),x.memory.load(STYLE,1),x.memory.load(OPTIONS,1),i['fetched_compare'],i['fetched_value'])
def endpoint(x,i,result=0):return E(**assembly_registers(x),memory=memory(x,i),result=claripy.BVV(result,8),constraints=tuple(x.solver.constraints))
def begin(i):
 l,p=project();q=l.address;p.hook(q+3,Sm83LoadAImmediate(TEXT,q+6),length=3);p.hook(q+7,Bound(DONE),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=DONE);return [endpoint(m.found[0],i)]
def step(i):
 l,p=project();q=l.address;p.hook(q+7,StartFetch(q+8),length=1);p.hook(q+8,Sm83CpRegister('c',q+9),length=1);p.hook(q+11,IncHl(q+12),length=1);p.hook(q+14,Bound(FINISH),length=1);s=p.factory.blank_state(addr=q+7);setup(s,i);m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {CONT,FINISH})
  if m.active:m.step()
 return [endpoint(x,i,1 if x.addr==FINISH else 0) for x in m.found]
def finish(i):
 l,p=project();q=l.address;p.hook(q+14,Fetch(q+15,'fetched_value'),length=1);p.hook(q+16,Sm83LoadAImmediate(ANIM,q+19),length=3);p.hook(q+19,Sm83DecRegister('a',q+20),length=1);p.hook(q+22,SetD(q+24,7),length=2);p.hook(q+26,Sm83ResRegister(7,'d',q+28),length=2);p.hook(q+28,Sm83LoadAImmediate(STYLE,q+31),length=3);p.hook(q+31,Sm83DecRegister('a',q+32),length=1);p.hook(q+34,SetD(q+36,6),length=2);p.hook(q+38,Sm83ResRegister(6,'d',q+40),length=2);p.hook(q+41,Sm83StoreAImmediate(OPTIONS,q+44),length=3);p.hook(q+44,Bound(DONE),length=1);s=p.factory.blank_state(addr=q+14);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=4);return [endpoint(x,i) for x in m.found]
def native(symbol,i,returns=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(symbol);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),result=x.regs.rax[7:0] if returns else claripy.BVV(0,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('part,asm,symbol,returns',(('begin',begin,'port_set_options_from_cursor_positions_begin',False),('step',step,'port_set_options_from_cursor_positions_step',True),('finish',finish,'port_set_options_from_cursor_positions_finish',False)))
def test_equivalence(part,asm,symbol,returns):
 i=inputs('options_'+part);assert_pathwise_equivalent(asm(i),native(symbol,i,returns),(*REGISTERS,'memory','result'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'SetOptionsFromCursorPositions');assert linked_bytes(ROM,l,45)==bytes.fromhex('219660fa3dcd4f2ab928032318f97e57fa3ecd3d2804cbfa1802cbbafa3fcd3d2804cbf21802cbb27aea55d3c9')
