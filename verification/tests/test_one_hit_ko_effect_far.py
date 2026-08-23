from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;DONE=0xEFFF
EXPECTED=bytes.fromhex('21577f060cc3d635')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class BankswitchBoundary(angr.SimProcedure):
 """Proven-hand-off boundary at `jp Bankswitch`: the dispatcher is not
 ported, so the observable is the complete far-call argument state."""
 def run(self):
  r=assembly_registers(self.state);self.jump(DONE)
def inputs(p):
 return symbolic_registers(p)
def setup(s,v):
 s.globals['bs']=claripy.BVV(0,64)
def assembly(v):
 l=symbol_location(SYMS,'OneHitKOEffect');t=symbol_location(SYMS,'Bankswitch');assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(t.address,BankswitchBoundary())
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v)
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=8);assert not m.errored and len(m.found)==1
 return [E(**assembly_registers(x),constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_one_hit_ko_effect_far');assert f
 s=p.factory.call_state(f.rebased_addr,NS);store_native_registers(s,NS,v);setup(s,v)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1
 return [E(**native_registers(x,NS),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_one_hit_ko_effect_far_pathwise_equivalence():
 v=inputs('one_hit_ko_effect_far');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,))
