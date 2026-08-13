from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr, claripy, pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate, Sm83CpRegister, Sm83LoadAImmediate, Sm83StoreAImmediate

ROOT=Path(__file__).resolve().parents[2]; NATIVE_ELF=ROOT/'verification/build/ports.elf'; ROM=ROOT/'pokered.gbc'; SYMBOLS=ROOT/'pokered.sym'
NATIVE_STATE=0x100000; STACK=0xd000; RETURN=0xffff; CONT=0xeffe; EFFECT=0xd11e; ENEMY_TYPE=0xcfcf; TYPE1=0xd019; TYPE2=0xd01a
KEYS=('enemy_move_type','player_type_1','player_type_2','effectiveness','fetched_attack_type','fetched_defense_type','fetched_multiplier')

class FetchRegister(angr.SimProcedure):
 def __init__(self,n,key,register='a',increment=False): super().__init__(); self.n=n; self.key=key; self.register=register; self.increment=increment
 def run(self):
  setattr(self.state.regs,self.register,self.state.globals[self.key])
  if self.increment:self.state.regs.hl=self.state.regs.hl+1
  self.jump(self.n)  # type: ignore[override]
class StartFetch(FetchRegister):
 def run(self):
  if self.state.globals.get('entered',False):self.jump(CONT);return
  self.state.globals['entered']=True;super().run()
class IncHl(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]

@dataclass(frozen=True)
class E:
 a:claripy.ast.BV; f:claripy.ast.BV; b:claripy.ast.BV; c:claripy.ast.BV; d:claripy.ast.BV; e:claripy.ast.BV; h:claripy.ast.BV; l:claripy.ast.BV; memory:claripy.ast.BV; result:claripy.ast.BV; constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 return i
def project():
 l=symbol_location(SYMBOLS,'AIGetTypeEffectiveness');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return l,p
def setup(s,i):
 set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
 s.memory.store(EFFECT,i['effectiveness']);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
def memory(x,i):return claripy.Concat(i['enemy_move_type'],i['player_type_1'],i['player_type_2'],x.memory.load(EFFECT,1),i['fetched_attack_type'],i['fetched_defense_type'],i['fetched_multiplier'])
def endpoint(x,i,result):return E(**assembly_registers(x),memory=memory(x,i),result=claripy.BVV(result,8),constraints=tuple(x.solver.constraints))
def begin(i):
 l,p=project();q=l.address
 p.hook(q,Sm83LoadAImmediate(ENEMY_TYPE,q+3),length=3);p.hook(q+7,FetchRegister(q+8,'player_type_1','b'),length=1);p.hook(q+8,IncHl(q+9),length=1);p.hook(q+9,FetchRegister(q+10,'player_type_2','c'),length=1);p.hook(q+12,Sm83StoreAImmediate(EFFECT,q+15),length=3)
 s=p.factory.blank_state(addr=q);setup(s,i);s.memory.store(ENEMY_TYPE,i['enemy_move_type']);m=p.factory.simulation_manager(s);m.explore(find=q+18);assert len(m.found)==1;return [endpoint(m.found[0],i,0)]
def step(i):
 l,p=project();q=l.address
 p.hook(q+18,StartFetch(q+19,'fetched_attack_type',increment=True),length=1);p.hook(q+19,Sm83CpImmediate(0xff,q+21),length=2);p.hook(q+22,Sm83CpRegister('d',q+23),length=1);p.hook(q+25,FetchRegister(q+26,'fetched_defense_type',increment=True),length=1);p.hook(q+26,Sm83CpRegister('b',q+27),length=1);p.hook(q+29,Sm83CpRegister('c',q+30),length=1);p.hook(q+34,IncHl(q+35),length=1);p.hook(q+35,IncHl(q+36),length=1);p.hook(q+38,FetchRegister(q+39,'fetched_multiplier'),length=1);p.hook(q+39,Sm83StoreAImmediate(EFFECT,q+42),length=3)
 s=p.factory.blank_state(addr=q+18);setup(s,i);m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {CONT,RETURN})
  if m.active:m.step()
 return [endpoint(x,i,0 if x.addr==CONT else 1) for x in m.found]
def native(symbol,i,returns):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(symbol);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),result=x.regs.rax[7:0] if returns else claripy.BVV(0,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('part,asm,symbol,returns',[('begin',begin,'port_ai_get_type_effectiveness_begin',False),('step',step,'port_ai_get_type_effectiveness_step',True)])
def test_equivalence(part,asm,symbol,returns):
 i=inputs('ai_type_'+part);assert_pathwise_equivalent(asm(i),native(symbol,i,returns),(*REGISTERS,'memory','result'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'AIGetTypeEffectiveness');assert linked_bytes(ROM,l,43)==bytes.fromhex('facfcf572119d046234e3e10ea1ed12174642afeffc8ba20092ab82809b928061801232318ec7eea1ed1c9')
