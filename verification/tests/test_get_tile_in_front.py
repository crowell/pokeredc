from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83CpImmediate,Sm83IncRegister,Sm83DecRegister,Sm83LoadAImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff;Y=0xd361;X=0xd362;FACING=0xc109;OUTPUT=0xcfc6
KEYS=('y','x','facing','tile_down','tile_up','tile_left','tile_right','output');TILES=(0xc484,0xc434,0xc45a,0xc45e)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in KEYS:i[n]=claripy.BVS(f'{p}_{n}',8)
 return i
def assembly(i):
 l=symbol_location(SYMBOLS,'_GetTileAndCoordsInFrontOfPlayer');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address
 for o,a in ((0,Y),(4,X),(8,FACING),(14,TILES[0]),(24,TILES[1]),(34,TILES[2]),(44,TILES[3])):p.hook(q+o,Sm83LoadAImmediate(a,q+o+3),length=3)
 p.hook(q+11,Sm83AndImmediate(0xff,q+12),length=1);p.hook(q+20,Sm83CpImmediate(4,q+22),length=2);p.hook(q+30,Sm83CpImmediate(8,q+32),length=2);p.hook(q+40,Sm83CpImmediate(12,q+42),length=2)
 for o,r in ((17,'d'),(47,'e')):p.hook(q+o,Sm83IncRegister(r,q+o+1),length=1)
 for o,r in ((27,'d'),(37,'e')):p.hook(q+o,Sm83DecRegister(r,q+o+1),length=1)
 p.hook(q+49,Sm83StoreAImmediate(OUTPUT,q+52),length=3);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.memory.store(Y,i['y']);s.memory.store(X,i['x']);s.memory.store(FACING,i['facing']);s.memory.store(OUTPUT,i['output'])
 for a,k in zip(TILES,KEYS[3:7]):s.memory.store(a,i[k])
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');ends=collect_returns(p,s,RETURN)
 return [E(**assembly_registers(e),memory=claripy.Concat(e.memory.load(Y,1),e.memory.load(X,1),e.memory.load(FACING,1),*(e.memory.load(a,1) for a in TILES),e.memory.load(OUTPUT,1)),constraints=tuple(e.solver.constraints)) for e in ends]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_get_tile_and_coords_in_front_of_player');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(e,NATIVE_STATE),memory=e.memory.load(NATIVE_STATE+8,8),constraints=tuple(e.solver.constraints)) for e in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('tile_front');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'_GetTileAndCoordsInFrontOfPlayer');assert linked_bytes(ROM,l,53)==bytes.fromhex('fa61d357fa62d35ffa09c1a72006fa84c414181cfe042006fa34c4151812fe082006fa5ac41d1808fe0c2004fa5ec41c4feac6cfc9')
