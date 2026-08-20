from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;DONE=0xEFFF
FIELDS=('joy_held','didnt_find_any_hidden_event','interacted_with_bookshelf','saved_bank','item_already_found','rom_bank','loaded_rom_bank')
EXPECTED_BODY=bytes.fromhex('f0b8f5f0b4cb47282c3e11ea0020e0b8cda069f0eea72010fa3ecdea0020e0b811da3ed5e9af180f060321507bcdd635f0db')
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
 joy_held:claripy.ast.BV;didnt_find_any_hidden_event:claripy.ast.BV;interacted_with_bookshelf:claripy.ast.BV;saved_bank:claripy.ast.BV;item_already_found:claripy.ast.BV;rom_bank:claripy.ast.BV;loaded_rom_bank:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Summary(angr.SimProcedure):
 def run(self)->None:
  j=self.state.globals['joy_held'];d=self.state.globals['didnt_find_any_hidden_event'];b=self.state.globals['interacted_with_bookshelf'];self.inhibit_autoret=True
  for cond,result in ((j&1==0,0xff),(claripy.And((j&1)!=0,d==0),0),(claripy.And((j&1)!=0,d!=0,b==0),0),(claripy.And((j&1)!=0,d!=0,b!=0),0xff)):
   st=self.state.copy();st.globals['item_already_found']=claripy.BVV(result,8);st.globals['rom_bank']=st.globals['saved_bank'];st.globals['loaded_rom_bank']=st.globals['saved_bank'];st.add_constraints(cond);self.successors.add_successor(st,DONE,claripy.BoolV(True),'Ijk_Boring')
def _assembly(i):
 l=symbol_location(SYMBOLS,'CheckForHiddenEventOrBookshelfOrCardKeyDoor');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q});p.hook(q,Summary(),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for f in FIELDS:s.globals[f]=i[f]
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=4);assert len(m.found)==4
 return [Endpoint(**assembly_registers(x),**{f:x.globals[f] for f in FIELDS},constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_check_for_hidden_event_or_bookshelf_or_card_key_door');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for off,f in enumerate(FIELDS,8):s.memory.store(NATIVE_STATE+off,i[f])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)>=3
 return [Endpoint(**native_registers(x,NATIVE_STATE),**{f:x.memory.load(NATIVE_STATE+off,1) for off,f in enumerate(FIELDS,8)},constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_check_for_hidden_event_or_bookshelf_or_card_key_door_pathwise_equivalence():
 i=symbolic_registers('hidden');
 for f in FIELDS:i[f]=claripy.BVS('hidden_'+f,8)
 assert_pathwise_equivalent(_assembly(i),_native(i),('a','f','b','c','d','e','h','l',*FIELDS))
def test_check_for_hidden_event_or_bookshelf_or_card_key_door_exact_linked_body():
 l=symbol_location(SYMBOLS,'CheckForHiddenEventOrBookshelfOrCardKeyDoor');assert linked_bytes(ROM,l,len(EXPECTED_BODY))==EXPECTED_BODY
