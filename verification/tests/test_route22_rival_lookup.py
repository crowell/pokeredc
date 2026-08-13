from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83CpRegister,Sm83LoadAImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;CONTINUE=0xeffe;DONE=0xefff;STARTER=0xd715;TRAINER=0xd05d
class Bound(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)  # type: ignore[override]
class FetchLoop(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):  # type: ignore[override]
  if self.state.globals.get('entered',False):self.jump(CONTINUE);return
  self.state.globals['entered']=True;self.state.regs.a=self.state.globals['key'];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
class FetchValue(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=self.state.globals['value'];self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in ('starter','key','value','trainer'):i[n]=claripy.BVS(f'{p}_{n}',8)
 return i
def project():
 l=symbol_location(SYMBOLS,'Route22GetRivalTrainerNoByStarterScript');return l,angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
def endpoint(x,i,result=0):return E(**assembly_registers(x),memory=claripy.Concat(x.memory.load(STARTER,1),i['key'],i['value'],x.memory.load(TRAINER,1)),result=claripy.BVV(result,8),constraints=tuple(x.solver.constraints))
def begin(i):
 l,p=project();p.hook(l.address,Sm83LoadAImmediate(STARTER,l.address+3),length=3);p.hook(l.address+4,Bound(DONE),length=1);s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,i);s.memory.store(STARTER,i['starter']);s.memory.store(TRAINER,i['trainer']);m=p.factory.simulation_manager(s);m.explore(find=DONE);return [endpoint(m.found[0],i)]
def step(i):
 l,p=project();loop=l.address+4;p.hook(loop,FetchLoop(loop+1),length=1);p.hook(loop+1,Sm83CpRegister('b',loop+2),length=1);p.hook(loop+7,Bound(DONE),length=1);s=p.factory.blank_state(addr=loop);set_assembly_registers(s,i);s.memory.store(STARTER,i['starter']);s.memory.store(TRAINER,i['trainer']);s.globals['key']=i['key'];s.globals['value']=i['value'];m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {CONTINUE,DONE})
  if m.active:m.step()
 return [endpoint(x,i,1 if x.addr==DONE else 0) for x in m.found]
def finish(i):
 l,p=project();p.hook(l.address+11,FetchValue(l.address+12),length=1);p.hook(l.address+12,Sm83StoreAImmediate(TRAINER,DONE),length=3);s=p.factory.blank_state(addr=l.address+11);set_assembly_registers(s,i);s.memory.store(STARTER,i['starter']);s.memory.store(TRAINER,i['trainer']);s.globals['key']=i['key'];s.globals['value']=i['value'];m=p.factory.simulation_manager(s);m.explore(find=DONE);return [endpoint(m.found[0],i)]
def native(sym,i,returns=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(i['starter'],i['key'],i['value'],i['trainer']));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,4),result=x.regs.rax[7:0] if returns else claripy.BVV(0,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('part,asm,c,ret',[('begin',begin,'port_route22_get_rival_trainer_no_begin',False),('step',step,'port_route22_get_rival_trainer_no_step',True),('finish',finish,'port_route22_get_rival_trainer_no_finish',False)])
def test_equivalence(part,asm,c,ret):
 i=inputs('route22_'+part);assert_pathwise_equivalent(asm(i),native(c,i,ret),(*REGISTERS,'memory','result'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'Route22GetRivalTrainerNoByStarterScript');assert linked_bytes(ROM,l,16)==bytes.fromhex('fa15d7472ab828032318f97eea5dd0c9')
