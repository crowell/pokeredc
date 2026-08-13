from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83CpImmediate,Sm83CpRegister,Sm83IncRegister,Sm83LoadAImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;CONT=0xeffd;FINISH=0xeffe;DONE=0xefff;GRAMMAR=0xd11e
KEYS=('grammar','fetched','saved_b','saved_c')
class Bound(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)  # type: ignore[override]
class StartFetch(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(CONT);return
  self.state.globals['entered']=True;self.state.regs.a=self.state.globals['fetched'];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
class RestoreBC(angr.SimProcedure):
 def run(self):self.state.regs.b=self.state.globals['saved_b'];self.state.regs.c=self.state.globals['saved_c'];self.jump(DONE)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in KEYS:i[n]=claripy.BVS(f'{p}_{n}',8)
 return i
def project():
 l=symbol_location(SYMBOLS,'GetMoveGrammar');return l,angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
def setup(s,i):set_assembly_registers(s,i);s.memory.store(GRAMMAR,i['grammar']);s.globals['fetched']=i['fetched'];s.globals['saved_b']=i['saved_b'];s.globals['saved_c']=i['saved_c']
def mem(x,i):return claripy.Concat(x.memory.load(GRAMMAR,1),i['fetched'],x.globals['saved_b'],x.globals['saved_c'])
def ep(x,i,r=0):return E(**assembly_registers(x),memory=mem(x,i),result=claripy.BVV(r,8),constraints=tuple(x.solver.constraints))
def begin(i):
 l,p=project();q=l.address+1;p.hook(q,Sm83LoadAImmediate(GRAMMAR,q+3),length=3);p.hook(q+9,Bound(DONE),length=1);s=p.factory.blank_state(addr=q);setup(s,i);s.globals['saved_b']=i['b'];s.globals['saved_c']=i['c'];m=p.factory.simulation_manager(s);m.explore(find=DONE);return [ep(m.found[0],i)]
def step(i):
 l,p=project();q=l.address+10;p.hook(q,StartFetch(q+1),length=1);p.hook(q+1,Sm83CpImmediate(0xff,q+3),length=2);p.hook(q+5,Sm83CpRegister('c',q+6),length=1);p.hook(q+8,Sm83AndImmediate(0xff,q+9),length=1);p.hook(q+11,Sm83IncRegister('b',q+12),length=1);p.hook(l.address+24,Bound(FINISH),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {CONT,FINISH})
  if m.active:m.step()
 return [ep(x,i,1 if x.addr==FINISH else 0) for x in m.found]
def finish(i):
 l,p=project();q=l.address+24;p.hook(q+1,Sm83StoreAImmediate(GRAMMAR,q+4),length=3);p.hook(q+4,RestoreBC(),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=DONE);return [ep(m.found[0],i)]
def native(sym,i,returns=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,4),result=x.regs.rax[7:0] if returns else claripy.BVV(0,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('part,asm,c,ret',[('begin',begin,'port_get_move_grammar_begin',False),('step',step,'port_get_move_grammar_step',True),('finish',finish,'port_get_move_grammar_finish',False)])
def test_equivalence(part,asm,c,ret):
 i=inputs('grammar_'+part);assert_pathwise_equivalent(asm(i),native(c,i,ret),(*REGISTERS,'memory','result'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'GetMoveGrammar');assert linked_bytes(ROM,l,30)==bytes.fromhex('c5fa1ed14f060021a35b2afeff2809b92806a720f50418f278ea1ed1c1c9')
