from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;DONE=0xEFFF
FIELDS=tuple(f'source{i}' for i in range(11))+tuple(f'destination{i}' for i in range(11))+('copy_a','copy_f')
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
 source0:claripy.ast.BV;source1:claripy.ast.BV;source2:claripy.ast.BV;source3:claripy.ast.BV;source4:claripy.ast.BV;source5:claripy.ast.BV;source6:claripy.ast.BV;source7:claripy.ast.BV;source8:claripy.ast.BV;source9:claripy.ast.BV;source10:claripy.ast.BV
 destination0:claripy.ast.BV;destination1:claripy.ast.BV;destination2:claripy.ast.BV;destination3:claripy.ast.BV;destination4:claripy.ast.BV;destination5:claripy.ast.BV;destination6:claripy.ast.BV;destination7:claripy.ast.BV;destination8:claripy.ast.BV;destination9:claripy.ast.BV;destination10:claripy.ast.BV
 copy_a:claripy.ast.BV;copy_f:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class NoOp(angr.SimProcedure):
 def __init__(self,next_address,length=1):super().__init__();self.next_address=next_address;self.length=length
 def run(self)->None:self.jump(self.next_address)
class CopyDataSummary(angr.SimProcedure):
 def run(self)->None:
  for n in range(11):self.state.globals[f'destination{n}']=self.state.globals[f'source{n}']
  self.state.regs.a=self.state.globals['copy_a'];self.state.regs.f=sm83_flags_to_z80(self.state.globals['copy_f']);self.jump(self.state.addr+3)
class Boundary(angr.SimProcedure):
 def run(self)->None:self.jump(DONE)
def _assembly(i):
 l=symbol_location(SYMBOLS,'GetPartyMonName');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q});p.hook(q,NoOp(q+1),length=1);p.hook(q+1,NoOp(q+2),length=1);p.hook(q+2,NoOp(q+5,3),length=3);p.hook(q+5,NoOp(q+8,3),length=3);p.hook(q+8,NoOp(q+9),length=1);p.hook(q+9,NoOp(q+12,3),length=3);p.hook(q+12,CopyDataSummary(),length=3);p.hook(q+15,NoOp(q+16),length=1);p.hook(q+16,NoOp(q+17),length=1);p.hook(q+17,NoOp(q+18),length=1);p.hook(q+18,Boundary(),length=1)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for f in FIELDS:s.globals[f]=i[f]
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=1);assert len(m.found)==1;x=m.found[0];return [Endpoint(**assembly_registers(x),**{f:x.globals[f] for f in FIELDS},constraints=tuple(x.solver.constraints))]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_get_party_mon_name');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for off,f in enumerate(FIELDS,8):s.memory.store(NATIVE_STATE+off,i[f])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1;x=m.deadended[0];return [Endpoint(**native_registers(x,NATIVE_STATE),**{f:x.memory.load(NATIVE_STATE+off,1) for off,f in enumerate(FIELDS,8)},constraints=tuple(x.solver.constraints))]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_get_party_mon_name_pathwise_equivalence():
 i=symbolic_registers('gpmn');i['copy_f']=claripy.Concat(claripy.BVS('gpmn_copy_flags',4),claripy.BVV(0,4))
 for f in FIELDS:
  if f!='copy_f':i[f]=claripy.BVS('gpmn_'+f,8)
 assert_pathwise_equivalent(_assembly(i),_native(i),('a','f','b','c','d','e','h','l',*FIELDS))
def test_get_party_mon_name_exact_body():
 l=symbol_location(SYMBOLS,'GetPartyMonName');assert linked_bytes(ROM,l,19)==bytes.fromhex('e5c5cd7d3a116dcdd5010b00cdb500d1c1e1c9')
