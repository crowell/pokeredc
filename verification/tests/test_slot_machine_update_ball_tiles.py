from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83IncRegister,Sm83LoadAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff;TILE=0xd08a
class Store(angr.SimProcedure):
 def __init__(self,n,index):super().__init__();self.n=n;self.index=index
 def run(self):
  address=self.state.regs.hl;v=list(self.state.globals['destination']);v[self.index]=self.state.regs.a;self.state.globals['destination']=v;self.state.globals['new_tile']=claripy.If(address==TILE,self.state.regs.a,self.state.globals['new_tile']);self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p);i['new_tile']=claripy.BVS(p+'_new_tile',8)
 for n in range(4):i[f'destination{n}']=claripy.BVS(f'{p}_destination{n}',8)
 return i
def alias_constraints(i):
 base=claripy.Concat(i['h'],i['l']);out=[]
 for n,offset in enumerate((0,13,20,33)):out.append(claripy.Or(base+offset!=TILE,i[f'destination{n}']==i['new_tile']))
 return tuple(out)
def assembly(i):
 l=symbol_location(SYMBOLS,'SlotMachine_UpdateBallTiles');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q,Sm83LoadAImmediate(TILE,q+3),length=3)
 for o,n in ((3,0),(8,1),(14,2),(19,3)):p.hook(q+o,Store(q+o+1,n),length=1)
 p.hook(q+7,Sm83AddHlRegisterPair('bc',q+8),length=1);p.hook(q+12,Sm83AddHlRegisterPair('bc',q+13),length=1);p.hook(q+13,Sm83IncRegister('a',q+14),length=1);p.hook(q+18,Sm83AddHlRegisterPair('bc',q+19),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.memory.store(TILE,i['new_tile']);s.globals['new_tile']=i['new_tile'];s.globals['destination']=[i[f'destination{n}'] for n in range(4)];s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');ends=collect_returns(p,s,RETURN);assert len(ends)==1;x=ends[0]
 return [E(**assembly_registers(x),memory=claripy.Concat(x.globals['new_tile'],*x.globals['destination']),constraints=alias_constraints(i)+tuple(x.solver.constraints))]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_slot_machine_update_ball_tiles');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(i['new_tile'],*(i[f'destination{n}'] for n in range(4))));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,5),constraints=alias_constraints(i)+tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('slot_ball_tiles');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'SlotMachine_UpdateBallTiles');assert linked_bytes(ROM,l,21)==bytes.fromhex('fa8ad077010d000977010700093c77010d000977c9')
