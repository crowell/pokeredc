from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;DONE=0xEFFF
FIELDS=('reload_a','reload_f','reload_b','reload_c','reload_d','reload_e','reload_h','reload_l','saved_h','saved_l')
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
 reload_a:claripy.ast.BV;reload_f:claripy.ast.BV;reload_b:claripy.ast.BV;reload_c:claripy.ast.BV;reload_d:claripy.ast.BV;reload_e:claripy.ast.BV;reload_h:claripy.ast.BV;reload_l:claripy.ast.BV;saved_h:claripy.ast.BV;saved_l:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class LoadHL(angr.SimProcedure):
 def run(self)->None:self.state.regs.h=0x6f;self.state.regs.l=0x48;self.jump(self.state.addr+3)
class CalleeNoOp(angr.SimProcedure):
 def run(self)->None:self.jump(self.state.addr+3)
class PopHL(angr.SimProcedure):
 def run(self)->None:self.state.regs.h=self.state.globals['saved_h'];self.state.regs.l=self.state.globals['saved_l'];self.jump(self.state.addr+1)
class ReloadSummary(angr.SimProcedure):
 def run(self)->None:
  for r,f in (('a','reload_a'),('b','reload_b'),('c','reload_c'),('d','reload_d'),('e','reload_e'),('h','reload_h'),('l','reload_l')):setattr(self.state.regs,r,self.state.globals[f])
  self.state.regs.f=sm83_flags_to_z80(self.state.globals['reload_f']);self.jump(self.state.addr+3)
class Boundary(angr.SimProcedure):
 def run(self)->None:self.jump(DONE)
def _assembly(i):
 l=symbol_location(SYMBOLS,'CancelledEvolution');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q});p.hook(q,LoadHL(),length=3);p.hook(q+3,CalleeNoOp(),length=3);p.hook(q+6,CalleeNoOp(),length=3);p.hook(q+9,PopHL(),length=1);p.hook(q+10,ReloadSummary(),length=3);p.hook(q+13,Boundary(),length=3)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for f in FIELDS:s.globals[f]=i[f]
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=1);assert len(m.found)==1;x=m.found[0];return [Endpoint(**assembly_registers(x),**{f:x.globals[f] for f in FIELDS},constraints=tuple(x.solver.constraints))]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_cancelled_evolution');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for off,f in enumerate(FIELDS,8):s.memory.store(NATIVE_STATE+off,i[f])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1;x=m.deadended[0];return [Endpoint(**native_registers(x,NATIVE_STATE),**{f:x.memory.load(NATIVE_STATE+off,1) for off,f in enumerate(FIELDS,8)},constraints=tuple(x.solver.constraints))]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_cancelled_evolution_pathwise_equivalence():
 i=symbolic_registers('ce');i['reload_f']=claripy.Concat(claripy.BVS('ce_reload_flags',4),claripy.BVV(0,4))
 for f in ('reload_a','reload_b','reload_c','reload_d','reload_e','reload_h','reload_l','saved_h','saved_l'):i[f]=claripy.BVS('ce_'+f,8)
 assert_pathwise_equivalent(_assembly(i),_native(i),('a','f','b','c','d','e','h','l',*FIELDS))
def test_cancelled_evolution_exact_body():
 l=symbol_location(SYMBOLS,'CancelledEvolution');assert linked_bytes(ROM,l,16)==bytes.fromhex('21486fcd493ccd0f19e1cd526fc32e6d')
