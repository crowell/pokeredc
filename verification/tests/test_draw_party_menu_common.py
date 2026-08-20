from __future__ import annotations
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;DONE=0xEFFF
FIELDS=('rom_bank','bankswitch_called')
EXPECTED_BODY=bytes.fromhex('0604c3d635')
class Endpoint:
 def __init__(self,regs,values,constraints):self.__dict__.update(regs);self.__dict__.update(values);self.constraints=tuple(constraints)
class Summary(angr.SimProcedure):
 def run(self)->None:
  st=self.state.copy();st.regs.b=claripy.BVV(4,8);st.globals['rom_bank']=claripy.BVV(4,8);st.globals['bankswitch_called']=claripy.BVV(1,8);self.inhibit_autoret=True;self.successors.add_successor(st,DONE,claripy.BoolV(True),'Ijk_Boring')
def _assembly(i):
 l=symbol_location(SYMBOLS,'DrawPartyMenuCommon');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q});p.hook(q,Summary(),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for f in FIELDS:s.globals[f]=i[f]
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=1);assert len(m.found)==1;x=m.found[0];return [Endpoint(assembly_registers(x),{f:x.globals[f] for f in FIELDS},x.solver.constraints)]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_draw_party_menu_common');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for off,f in enumerate(FIELDS,8):s.memory.store(NATIVE_STATE+off,i[f])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1;x=m.deadended[0];return [Endpoint(native_registers(x,NATIVE_STATE),{f:x.memory.load(NATIVE_STATE+off,1) for off,f in enumerate(FIELDS,8)},x.solver.constraints)]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_draw_party_menu_common_pathwise_equivalence():
 i=symbolic_registers('party_common');
 for f in FIELDS:i[f]=claripy.BVS('party_common_'+f,8)
 assert_pathwise_equivalent(_assembly(i),_native(i),('a','f','b','c','d','e','h','l',*FIELDS))
def test_draw_party_menu_common_exact_linked_body():
 l=symbol_location(SYMBOLS,'DrawPartyMenuCommon');assert linked_bytes(ROM,l,len(EXPECTED_BODY))==EXPECTED_BODY
