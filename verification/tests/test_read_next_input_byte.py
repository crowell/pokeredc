from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83LoadAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff;PTR=0xd0ab
class Fetch(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  address=self.state.regs.hl;lo=self.state.globals['pointer_low'];hi=self.state.globals['pointer_high'];src=self.state.globals['source'];self.state.regs.a=claripy.If(address==PTR,lo,claripy.If(address==PTR+1,hi,src));self.state.regs.hl=address+1;self.state.globals['target']=address;self.jump(self.n)  # type: ignore[override]
class StorePtr(angr.SimProcedure):
 def __init__(self,n,high):super().__init__();self.n=n;self.high=high
 def run(self):
  key='pointer_high' if self.high else 'pointer_low';self.state.globals[key]=self.state.regs.a;target=self.state.globals['target'];self.state.globals['source']=claripy.If(target==PTR+(1 if self.high else 0),self.state.regs.a,self.state.globals['source']);self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in ('pointer_low','pointer_high','source'):i[n]=claripy.BVS(f'{p}_{n}',8)
 return i
def constraints(i):
 a=claripy.Concat(i['pointer_high'],i['pointer_low']);return (claripy.Or(a!=PTR,i['source']==i['pointer_low']),claripy.Or(a!=PTR+1,i['source']==i['pointer_high']))
def assembly(i):
 l=symbol_location(SYMBOLS,'ReadNextInputByte');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q,Sm83LoadAImmediate(PTR,q+3),length=3);p.hook(q+4,Sm83LoadAImmediate(PTR+1,q+7),length=3);p.hook(q+8,Fetch(q+9),length=1);p.hook(q+11,StorePtr(q+14,False),length=3);p.hook(q+15,StorePtr(q+18,True),length=3);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.memory.store(PTR,i['pointer_low']);s.memory.store(PTR+1,i['pointer_high']);s.globals['pointer_low']=i['pointer_low'];s.globals['pointer_high']=i['pointer_high'];s.globals['source']=i['source'];s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');ends=collect_returns(p,s,RETURN)
 return [E(**assembly_registers(x),memory=claripy.Concat(x.globals['pointer_low'],x.globals['pointer_high'],x.globals['source']),constraints=constraints(i)+tuple(x.solver.constraints)) for x in ends]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_read_next_input_byte');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(i['pointer_low'],i['pointer_high'],i['source']));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,3),constraints=constraints(i)+tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('read_next_input');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'ReadNextInputByte');assert linked_bytes(ROM,l,20)==bytes.fromhex('faabd06ffaacd0672a477deaabd07ceaacd078c9')
