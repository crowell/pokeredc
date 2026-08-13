from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AndImmediate,Sm83DecRegister,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;CONT=0xeffe;DONE=0xefff;ASLEEP=0xcd3d
class Bound(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)  # type: ignore[override]
class StartLoad(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(CONT);return
  self.state.globals['entered']=True;self.state.regs.a=self.state.globals['fetched'];self.jump(self.n)  # type: ignore[override]
class SaveAF(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['saved_a']=self.state.regs.a;self.state.globals['saved_f']=self.state.regs.f;self.jump(self.n)  # type: ignore[override]
class RestoreAF(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=self.state.globals['saved_a'];self.state.regs.f=self.state.globals['saved_f'];self.jump(self.n)  # type: ignore[override]
class AndB(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=self.state.regs.a&self.state.regs.b;self.state.regs.f=claripy.BVV(0x10,8)|claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8));self.jump(self.n)  # type: ignore[override]
class StoreStatus(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['written']=self.state.regs.a;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in ('were_asleep','fetched','written'):i[n]=claripy.BVS(f'{p}_{n}',8)
 return i
def mem(x,i):return claripy.Concat(x.memory.load(ASLEEP,1),i['fetched'],x.globals.get('written',i['written']))
def begin(i):
 l=symbol_location(SYMBOLS,'WakeUpEntireParty');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});p.hook(l.address+5,Bound(DONE),length=1);s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,i);s.memory.store(ASLEEP,i['were_asleep']);s.globals['fetched']=i['fetched'];s.globals['written']=i['written'];m=p.factory.simulation_manager(s);m.explore(find=DONE);x=m.found[0];return [E(**assembly_registers(x),memory=mem(x,i),result=claripy.BVV(0,8),constraints=tuple(x.solver.constraints))]
def step(i):
 l=symbol_location(SYMBOLS,'WakeUpEntireParty');q=l.address+5;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q});p.hook(q,StartLoad(q+1),length=1);p.hook(q+1,SaveAF(q+2),length=1);p.hook(q+2,Sm83AndImmediate(7,q+4),length=2);p.hook(q+8,Sm83StoreAImmediate(ASLEEP,q+11),length=3);p.hook(q+11,RestoreAF(q+12),length=1);p.hook(q+12,AndB(q+13),length=1);p.hook(q+13,StoreStatus(q+14),length=1);p.hook(q+14,Sm83AddHlRegisterPair('de',q+15),length=1);p.hook(q+15,Sm83DecRegister('c',q+16),length=1);p.hook(q+18,Bound(DONE),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.memory.store(ASLEEP,i['were_asleep']);s.globals['fetched']=i['fetched'];s.globals['written']=i['written'];m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {CONT,DONE})
  if m.active:m.step()
 return [E(**assembly_registers(x),memory=mem(x,i),result=claripy.BVV(1 if x.addr==DONE else 0,8),constraints=tuple(x.solver.constraints)) for x in m.found]
def native(sym,i,returns=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(i['were_asleep'],i['fetched'],i['written']));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,3),result=x.regs.rax[7:0] if returns else claripy.BVV(0,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('part,asm,c,ret',[('begin',begin,'port_wake_up_entire_party_begin',False),('step',step,'port_wake_up_entire_party_step',True)])
def test_equivalence(part,asm,c,ret):
 i=inputs('wake_'+part);assert_pathwise_equivalent(asm(i),native(c,i,ret),(*REGISTERS,'memory','result'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'WakeUpEntireParty');assert linked_bytes(ROM,l,24)==bytes.fromhex('112c000e067ef5e60728053e01ea3dcdf1a077190d20eec9')
