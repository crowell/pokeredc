from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;NATIVE_CALLBACK=0x100100;DONE=0xefff
class Boundary(angr.SimProcedure):
 def __init__(self,full):super().__init__();self.full=full
 def run(self):
  self.state.globals['dispatched']=claripy.BVV(1,8)
  if self.full:
   cb=self.state.globals['callback']
   for r in REGISTERS:setattr(self.state.regs,r,sm83_flags_to_z80(cb[r]) if r=='f' else cb[r])
  self.jump(DONE)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p);i['dispatched']=claripy.BVS(p+'_dispatched',8)
 for r,v in symbolic_registers(p+'_callback').items():i['callback_'+r]=v
 return i
def assembly(i,full):
 l=symbol_location(SYMBOLS,'LoadMonPartySpriteGfx');tail=symbol_location(SYMBOLS,'LoadAnimSpriteGfx').address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});p.hook(tail,Boundary(full));s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,i);s.globals['dispatched']=claripy.BVV(0,8);s.globals['callback']={r:i['callback_'+r] for r in REGISTERS};m=p.factory.simulation_manager(s);m.explore(find=DONE);return [E(**assembly_registers(x),memory=x.globals['dispatched'],constraints=tuple(x.solver.constraints)) for x in m.found]
def native(i,full):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);name='port_load_mon_party_sprite_gfx' if full else 'port_load_mon_party_sprite_gfx_begin';fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE,NATIVE_CALLBACK) if full else p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i['dispatched'])
 if full:store_native_registers(s,NATIVE_CALLBACK,{r:i['callback_'+r] for r in REGISTERS})
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('full',(False,True))
def test_equivalence(full):
 i=inputs('mon_party_gfx_'+str(full));assert_pathwise_equivalent(assembly(i,full),native(i,full),(*REGISTERS,'memory'))
def test_exact_prefix():
 l=symbol_location(SYMBOLS,'LoadMonPartySpriteGfx');assert linked_bytes(ROM,l,5)==bytes.fromhex('21c0573e1c');assert symbol_location(SYMBOLS,'MonPartySpritePointers').address==0x57c0
