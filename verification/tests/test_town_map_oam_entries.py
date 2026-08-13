from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AndImmediate,Sm83LoadAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;BOUNDARY=0xefff;BASE_TILE=0xcd5b
CASES=(('WriteTownMapSpriteOAM','port_write_town_map_sprite_oam_begin',8,45),('WritePlayerOrBirdSpriteOAM','port_write_player_or_bird_sprite_oam_begin',12,57))
class Bound(angr.SimProcedure):
 def run(self):self.jump(BOUNDARY)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p);i['base_tile']=claripy.BVS(p+'_base_tile',8)
 for n in range(16):i[f'output{n}']=claripy.BVS(f'{p}_output{n}',8)
 return i
def assembly(symbol,length,i):
 l=symbol_location(SYMBOLS,symbol);p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address
 if symbol=='WriteTownMapSpriteOAM':p.hook(q+4,Sm83AddHlRegisterPair('bc',q+5),length=1)
 else:
  p.hook(q,Sm83LoadAImmediate(BASE_TILE,q+3),length=3);p.hook(q+3,Sm83AndImmediate(0xff,q+4),length=1)
 p.hook(q+length,Bound(),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.memory.store(BASE_TILE,i['base_tile']);s.regs.sp=STACK;m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);assert not m.errored
 return [E(**assembly_registers(x),memory=claripy.Concat(x.memory.load(BASE_TILE,1),*(i[f'output{n}'] for n in range(16))),constraints=tuple(x.solver.constraints)) for x in m.found]
def native(symbol,i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(symbol);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(i['base_tile'],*(i[f'output{n}'] for n in range(16))));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,17),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('symbol,c_symbol,setup,_full',CASES)
def test_setup(symbol,c_symbol,setup,_full):
 i=inputs(symbol.lower());assert_pathwise_equivalent(assembly(symbol,setup,i),native(c_symbol,i),(*REGISTERS,'memory'))
@pytest.mark.parametrize('symbol,_c_symbol,_setup,full',CASES)
def test_exact_body(symbol,_c_symbol,_setup,full):
 l=symbol_location(SYMBOLS,symbol);assert len(linked_bytes(ROM,l,full))==full
 tail=bytes.fromhex('110202d5c578227922fa5bcd223cea5bcdaf22143e08814f1d20eac1d13e0880471520dfc9')
 prefix={'WriteTownMapSpriteOAM':bytes.fromhex('e521fcfc09444de1'),'WritePlayerOrBirdSpriteOAM':bytes.fromhex('fa5bcda72190c328032180c3')}[symbol]
 if symbol=='WritePlayerOrBirdSpriteOAM':prefix+=bytes.fromhex('e521fcfc09444de1')
 assert linked_bytes(ROM,l,full)==prefix+tail
