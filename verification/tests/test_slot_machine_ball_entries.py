from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83DecRegister,Sm83LoadAImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;BOUNDARY=0xefff;TILE=0xd08a;BET=0xcd50
SETUPS=(('SlotMachine_UpdateThreeCoinBallTiles',0,'port_slot_machine_update_three_coin_ball_tiles_begin0',0xc3cb),('SlotMachine_UpdateThreeCoinBallTiles',6,'port_slot_machine_update_three_coin_ball_tiles_begin1',0xc46b),('SlotMachine_UpdateTwoCoinBallTiles',0,'port_slot_machine_update_two_coin_ball_tiles_begin0',0xc3f3),('SlotMachine_UpdateTwoCoinBallTiles',6,'port_slot_machine_update_two_coin_ball_tiles_begin1',0xc443),('SlotMachine_UpdateOneCoinBallTiles',0,'port_slot_machine_update_one_coin_ball_tiles_begin',0xc41b))
class Bound(angr.SimProcedure):
 def run(self):self.jump(BOUNDARY)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p);i['new_tile']=claripy.BVS(p+'_new_tile',8);i['bet']=claripy.BVS(p+'_bet',8)
 for n in range(20):i[f'destination{n}']=claripy.BVS(f'{p}_destination{n}',8)
 return i
def memory_values(i):return claripy.Concat(i['new_tile'],i['bet'],*(i[f'destination{n}'] for n in range(20)))
def project(symbol):
 l=symbol_location(SYMBOLS,symbol);return l,angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
def setup_assembly(symbol,offset,i):
 l,p=project(symbol);q=l.address+offset;p.hook(q+3,Bound(),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);x=m.found[0];return [E(**assembly_registers(x),memory=memory_values(i),result=claripy.BVV(0,8),constraints=tuple(x.solver.constraints))]
def put_assembly(i):
 l,p=project('SlotMachine_PutOutLitBalls');target=symbol_location(SYMBOLS,'SlotMachine_UpdateThreeCoinBallTiles').address;p.hook(l.address+2,Sm83StoreAImmediate(TILE,l.address+5),length=3);p.hook(target,Bound(),length=1);s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,i);s.memory.store(TILE,i['new_tile']);m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);x=m.found[0];return [E(**assembly_registers(x),memory=claripy.Concat(x.memory.load(TILE,1),i['bet'],*(i[f'destination{n}'] for n in range(20))),result=claripy.BVV(0,8),constraints=tuple(x.solver.constraints))]
def light_assembly(i):
 l,p=project('SlotMachine_LightBalls');three=symbol_location(SYMBOLS,'SlotMachine_UpdateThreeCoinBallTiles').address;two=symbol_location(SYMBOLS,'SlotMachine_UpdateTwoCoinBallTiles').address;one=symbol_location(SYMBOLS,'SlotMachine_UpdateOneCoinBallTiles').address;q=l.address;p.hook(q+2,Sm83StoreAImmediate(TILE,q+5),length=3);p.hook(q+5,Sm83LoadAImmediate(BET,q+8),length=3);p.hook(q+8,Sm83DecRegister('a',q+9),length=1);p.hook(q+11,Sm83DecRegister('a',q+12),length=1)
 for address in (one,two,three):p.hook(address,Bound(),length=1)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.memory.store(TILE,i['new_tile']);s.memory.store(BET,i['bet']);m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY,num_find=3)
 ends=[]
 for x in m.found:
  mode=claripy.If(i['bet']==1,claripy.BVV(1,8),claripy.If(i['bet']==2,claripy.BVV(2,8),claripy.BVV(3,8)))
  ends.append(E(**assembly_registers(x),memory=claripy.Concat(x.memory.load(TILE,1),x.memory.load(BET,1),*(i[f'destination{n}'] for n in range(20))),result=mode,constraints=tuple(x.solver.constraints)))
 return ends
def native(symbol,i,returns=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(symbol);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,memory_values(i));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,22),result=x.regs.rax[7:0] if returns else claripy.BVV(0,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('symbol,offset,c_symbol,_address',SETUPS)
def test_fixed_setup(symbol,offset,c_symbol,_address):
 i=inputs(c_symbol);assert_pathwise_equivalent(setup_assembly(symbol,offset,i),native(c_symbol,i),(*REGISTERS,'memory','result'))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_put_out_setup():
 i=inputs('put_out_balls');assert_pathwise_equivalent(put_assembly(i),native('port_slot_machine_put_out_lit_balls_begin',i),(*REGISTERS,'memory','result'))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_light_setup():
 i=inputs('light_balls');assert_pathwise_equivalent(light_assembly(i),native('port_slot_machine_light_balls_begin',i,True),(*REGISTERS,'memory','result'))
def test_exact_cascades():
 tail=bytes.fromhex('fa8ad077010d000977010700093c77010d000977c9');one=bytes.fromhex('211bc4')+tail;two=bytes.fromhex('21f3c3cdfe772143c4cdfe77')+one;three=bytes.fromhex('21cbc3cdfe77216bc4cdfe77')+two
 assert linked_bytes(ROM,symbol_location(SYMBOLS,'SlotMachine_UpdateOneCoinBallTiles'),len(one))==one
 assert linked_bytes(ROM,symbol_location(SYMBOLS,'SlotMachine_UpdateTwoCoinBallTiles'),len(two))==two
 assert linked_bytes(ROM,symbol_location(SYMBOLS,'SlotMachine_UpdateThreeCoinBallTiles'),len(three))==three
 assert linked_bytes(ROM,symbol_location(SYMBOLS,'SlotMachine_PutOutLitBalls'),7)==bytes.fromhex('3e23ea8ad0180e')
 assert linked_bytes(ROM,symbol_location(SYMBOLS,'SlotMachine_LightBalls'),14)==bytes.fromhex('3e14ea8ad0fa50cd3d281b3d280c')
