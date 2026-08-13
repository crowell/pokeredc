from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83CpImmediate,Sm83DecRegister,Sm83IncRegister,Sm83SetAtHl,Sm83StoreAHighImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff
Y=0xd361;X=0xd362;FACING=0xc109;PLAYER_FACING=0xffdb;COLLISION=0xd71c;TILE_FRONT=0xc6ea;TILES=(0xc4ac,0xc40c,0xc458,0xc460)
KEYS=('y','x','facing','tile_down','tile_up','tile_left','tile_right','player_facing_bits','collision_result','tile_in_front')
class XorA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=0;self.state.regs.f=0x40;self.jump(self.n)  # type: ignore[override]
class Fetch(angr.SimProcedure):
 def __init__(self,n,key,register='a',inc=False):super().__init__();self.n=n;self.key=key;self.register=register;self.inc=inc
 def run(self):setattr(self.state.regs,self.register,self.state.globals[self.key]);self.state.regs.hl=self.state.regs.hl+(1 if self.inc else 0);self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 return i
def assembly(i):
 l=symbol_location(SYMBOLS,'GetTileTwoStepsInFrontOfPlayer');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address
 p.hook(q,XorA(q+1),length=1);p.hook(q+1,Sm83StoreAHighImmediate(0xdb,q+3),length=2);p.hook(q+6,Fetch(q+7,'y',inc=True),length=1);p.hook(q+8,Fetch(q+9,'x','e'),length=1);p.hook(q+9,Fetch(q+12,'facing'),length=3);p.hook(q+12,Sm83AndImmediate(0xff,q+13),length=1)
 for o,bit in ((18,0),(33,1),(48,2),(63,3)):p.hook(q+o,Sm83SetAtHl(bit,q+o+2),length=2)
 for o,key in ((20,'tile_down'),(35,'tile_up'),(50,'tile_left'),(65,'tile_right')):p.hook(q+o,Fetch(q+o+3,key),length=3)
 for o,v in ((26,4),(41,8),(56,12)):p.hook(q+o,Sm83CpImmediate(v,q+o+2),length=2)
 p.hook(q+23,Sm83IncRegister('d',q+24),length=1);p.hook(q+38,Sm83DecRegister('d',q+39),length=1);p.hook(q+53,Sm83DecRegister('e',q+54),length=1);p.hook(q+68,Sm83IncRegister('e',q+69),length=1);p.hook(q+70,Sm83StoreAImmediate(COLLISION,q+73),length=3);p.hook(q+73,Sm83StoreAImmediate(TILE_FRONT,q+76),length=3)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for a,k in ((Y,'y'),(X,'x'),(FACING,'facing'),(PLAYER_FACING,'player_facing_bits'),(COLLISION,'collision_result'),(TILE_FRONT,'tile_in_front')):s.memory.store(a,i[k])
 for a,k in zip(TILES,KEYS[3:7]):s.memory.store(a,i[k])
 for k in KEYS:s.globals[k]=i[k]
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');ends=collect_returns(p,s,RETURN)
 return [E(**assembly_registers(x),memory=claripy.Concat(x.memory.load(Y,1),x.memory.load(X,1),x.memory.load(FACING,1),*(x.memory.load(a,1) for a in TILES),x.memory.load(PLAYER_FACING,1),x.memory.load(COLLISION,1),x.memory.load(TILE_FRONT,1)),constraints=tuple(x.solver.constraints)) for x in ends]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_get_tile_two_steps_in_front_of_player');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('tile_two_steps');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'GetTileTwoStepsInFrontOfPlayer');assert linked_bytes(ROM,l,77)==bytes.fromhex('afe0db2161d32a575efa09c1a7200b21dbffcbc6faacc414182bfe04200b21dbffcbcefa0cc415181cfe08200b21dbffcbd6fa58c41d180dfe0c200921dbffcbdefa60c41c4fea1cd7eac6cfc9')
