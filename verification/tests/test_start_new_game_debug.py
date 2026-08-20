from __future__ import annotations
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;DONE=0xEFFF
FIELDS=('joy_pressed','joy_held','joy5','cable_club_destination_map','status_flags6','entering_cable_club','oak_speech_called','delay_frames_called','reset_sprite_called','enter_map_called')
EXPECTED_BODY=bytes.fromhex('cd15610e14cd3937')
class Endpoint:
 def __init__(self,regs,values,constraints):self.__dict__.update(regs);self.__dict__.update(values);self.constraints=tuple(constraints)
class Summary(angr.SimProcedure):
 def run(self)->None:
  entering=self.state.globals['entering_cable_club'];self.inhibit_autoret=True
  for cond,entered in ((entering==0,True),(entering!=0,False)):
   st= self.state.copy();st.globals['joy_pressed']=claripy.BVV(0,8);st.globals['joy_held']=claripy.BVV(0,8);st.globals['joy5']=claripy.BVV(0,8);st.globals['cable_club_destination_map']=claripy.BVV(0,8);st.globals['status_flags6']=st.globals['status_flags6']|2;st.globals['oak_speech_called']=claripy.BVV(1,8);st.globals['delay_frames_called']=claripy.BVV(2,8);st.globals['reset_sprite_called']=claripy.BVV(1,8);st.globals['enter_map_called']=claripy.BVV(1 if entered else 0,8);st.add_constraints(cond);self.successors.add_successor(st,DONE,claripy.BoolV(True),'Ijk_Boring')
def _assembly(i):
 l=symbol_location(SYMBOLS,'StartNewGameDebug');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q});p.hook(q,Summary(),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for f in FIELDS:s.globals[f]=i[f]
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=2);assert len(m.found)==2
 return [Endpoint(assembly_registers(x),{f:x.globals[f] for f in FIELDS},x.solver.constraints) for x in m.found]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_start_new_game_debug');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for off,f in enumerate(FIELDS,8):s.memory.store(NATIVE_STATE+off,i[f])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)>=1
 return [Endpoint(native_registers(x,NATIVE_STATE),{f:x.memory.load(NATIVE_STATE+off,1) for off,f in enumerate(FIELDS,8)},x.solver.constraints) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_start_new_game_debug_pathwise_equivalence():
 i=symbolic_registers('new_debug')
 for f in FIELDS:i[f]=claripy.BVS('new_debug_'+f,8)
 assert_pathwise_equivalent(_assembly(i),_native(i),('a','f','b','c','d','e','h','l',*FIELDS))
def test_start_new_game_debug_exact_linked_body():
 l=symbol_location(SYMBOLS,'StartNewGameDebug');assert linked_bytes(ROM,l,len(EXPECTED_BODY))==EXPECTED_BODY
