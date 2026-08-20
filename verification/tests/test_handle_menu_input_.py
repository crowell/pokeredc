from __future__ import annotations
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;DONE=0xEFFF
FIELDS=('joy5','menu_joypad_poll_count','menu_wrapping_enabled','current_menu_item','max_menu_item','check_for_180_degree_turn','anim_counter','menu_watched_keys')
EXPECTED_BODY=bytes.fromhex('f08bf5f08cf5afe08b3e06e08c')
class Endpoint:
 def __init__(self,regs,values,constraints):self.__dict__.update(regs);self.__dict__.update(values);self.constraints=tuple(constraints)
class Summary(angr.SimProcedure):
 def run(self)->None:
  joy=self.state.globals['joy5'];poll=self.state.globals['menu_joypad_poll_count'];wrap=self.state.globals['menu_wrapping_enabled'];cur=self.state.globals['current_menu_item'];maxi=self.state.globals['max_menu_item'];self.inhibit_autoret=True
  no=self.state.copy();no.globals['menu_joypad_poll_count']=claripy.BVV(0,8);no.globals['menu_wrapping_enabled']=claripy.BVV(0,8);no.globals['anim_counter']=claripy.BVV(0,8);no.regs.a=claripy.BVV(0,8);no.add_constraints(joy==0);self.successors.add_successor(no,DONE,claripy.BoolV(True),'Ijk_Boring')
  key=self.state.copy();up=(joy&0x40)!=0;down=(joy&0x80)!=0;upv=claripy.If(cur!=0,cur-1,claripy.If(wrap!=0,maxi,cur));downraw=cur+1;downv=claripy.If(downraw>maxi,claripy.If(wrap!=0,claripy.BVV(0,8),maxi),downraw);key.globals['current_menu_item']=claripy.If(up,upv,claripy.If(down,downv,cur));key.globals['check_for_180_degree_turn']=claripy.BVV(0,8);key.globals['menu_wrapping_enabled']=claripy.BVV(0,8);key.globals['anim_counter']=claripy.BVV(0,8);key.regs.a=joy;key.add_constraints(joy!=0);self.successors.add_successor(key,DONE,claripy.BoolV(True),'Ijk_Boring')
def _assembly(i):
 l=symbol_location(SYMBOLS,'HandleMenuInput_');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q});p.hook(q,Summary(),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for f in FIELDS:s.globals[f]=i[f]
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=2);assert len(m.found)==2
 return [Endpoint(assembly_registers(x),{f:x.globals[f] for f in FIELDS},x.solver.constraints) for x in m.found]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_handle_menu_input_');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for off,f in enumerate(FIELDS,8):s.memory.store(NATIVE_STATE+off,i[f])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and m.deadended
 return [Endpoint(native_registers(x,NATIVE_STATE),{f:x.memory.load(NATIVE_STATE+off,1) for off,f in enumerate(FIELDS,8)},x.solver.constraints) for x in m.deadended]
@pytest.mark.parametrize('poll_value',[0,1,3])
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_handle_menu_input_pathwise_equivalence(poll_value):
 i=symbolic_registers('menu');
 for f in FIELDS:i[f]=claripy.BVS('menu_'+f,8)
 i['menu_joypad_poll_count']=claripy.BVV(poll_value,8)
 assert_pathwise_equivalent(_assembly(i),_native(i),('a','f',*FIELDS))
def test_handle_menu_input_exact_linked_body():
 l=symbol_location(SYMBOLS,'HandleMenuInput_');assert linked_bytes(ROM,l,len(EXPECTED_BODY))==EXPECTED_BODY
