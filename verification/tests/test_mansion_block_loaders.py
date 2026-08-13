from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;NATIVE_CALLBACK=0x100100;NATIVE_GLOBAL=0x100200;STACK=0xd000;RETURN=0xffff;KEYS=('new_tile_block_id','dispatched')
class StoreBlock(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['new_tile_block_id']=self.state.regs.a;self.jump(self.n)  # type: ignore[override]
class Callback(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  cb=self.state.globals['callback']
  for r in REGISTERS:setattr(self.state.regs,r,sm83_flags_to_z80(cb[r]) if r=='f' else cb[r])
  self.state.globals['new_tile_block_id']=cb['new_tile_block_id'];self.state.globals['dispatched']=claripy.BVV(1,8);self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p);i['new_tile_block_id']=claripy.BVS(p+'_block',8);i['dispatched']=claripy.BVS(p+'_dispatched',8)
 for r,v in symbolic_registers(p+'_callback').items():i['callback_'+r]=v
 i['callback_new_tile_block_id']=claripy.BVS(p+'_callback_block',8);return i
def assembly(symbol,i):
 l=symbol_location(SYMBOLS,symbol);tail=symbol_location(SYMBOLS,'Mansion1ReplaceBlock').address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q+2,StoreBlock(q+5),length=3);p.hook(tail+2,Callback(tail+5),length=3);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.globals['new_tile_block_id']=i['new_tile_block_id'];s.globals['dispatched']=claripy.BVV(0,8);s.globals['callback']={r:i['callback_'+r] for r in REGISTERS}|{'new_tile_block_id':i['callback_new_tile_block_id']};s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');return [E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[k] for k in KEYS)),constraints=tuple(x.solver.constraints)) for x in collect_returns(p,s,RETURN)]
def native(symbol,i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(symbol);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE,NATIVE_CALLBACK,NATIVE_GLOBAL);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(i['new_tile_block_id'],i['dispatched']));store_native_registers(s,NATIVE_CALLBACK,{r:i['callback_'+r] for r in REGISTERS});s.memory.store(NATIVE_GLOBAL,i['callback_new_tile_block_id']);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,2),constraints=tuple(x.solver.constraints)) for x in m.deadended]
CASES=(('Mansion1LoadHorizontalGateBlock','port_mansion1_load_horizontal_gate_block'),('Mansion1LoadEmptyFloorTileBlock','port_mansion1_load_empty_floor_tile_block'))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('asm_symbol,c_symbol',CASES)
def test_equivalence(asm_symbol,c_symbol):
 i=inputs(c_symbol);assert_pathwise_equivalent(assembly(asm_symbol,i),native(c_symbol,i),(*REGISTERS,'memory'))
def test_exact_bodies():
 a=symbol_location(SYMBOLS,'Mansion1LoadHorizontalGateBlock');assert linked_bytes(ROM,a,7)==bytes.fromhex('3e2dea9fd01805');b=symbol_location(SYMBOLS,'Mansion1LoadEmptyFloorTileBlock');assert linked_bytes(ROM,b,5)==bytes.fromhex('3e0eea9fd0');t=symbol_location(SYMBOLS,'Mansion1ReplaceBlock');assert linked_bytes(ROM,t,6)==bytes.fromhex('3e17cd6d3ec9');assert symbol_location(SYMBOLS,'wNewTileBlockID').address==0xd09f
