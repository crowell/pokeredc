from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;DONE=0xEFFF
FIELDS=('gym_leader_no','cur_opponent','fade_control','low_health_alarm','sound_id','audio_rom_bank','audio_saved_bank','stop_sound_called','delay_frame_called','play_music_called')
EXPECTED_BODY=bytes.fromhex('afeac7cfea83d03deaeec0cdb123cdaf200e08fa5cd0a728043eea181dfa59d0fec83814fef3280cfef720043eea180a3eed18063ef318023ef0c3a123')
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
 gym_leader_no:claripy.ast.BV;cur_opponent:claripy.ast.BV;fade_control:claripy.ast.BV;low_health_alarm:claripy.ast.BV;sound_id:claripy.ast.BV;audio_rom_bank:claripy.ast.BV;audio_saved_bank:claripy.ast.BV;stop_sound_called:claripy.ast.BV;delay_frame_called:claripy.ast.BV;play_music_called:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Summary(angr.SimProcedure):
 def run(self)->None:
  g=self.state.globals['gym_leader_no'];o=self.state.globals['cur_opponent'];base=claripy.And(g==0,o>=200);self.inhibit_autoret=True
  branches=((g!=0,0xea),(claripy.And(g==0,o<200),0xf0),(claripy.And(base,o==243),0xf3),(claripy.And(base,o!=243,o==247),0xea),(claripy.And(base,o!=243,o!=247),0xed))
  for cond,music in branches:
   st=self.state.copy();st.globals['fade_control']=claripy.BVV(0,8);st.globals['low_health_alarm']=claripy.BVV(0,8);st.globals['sound_id']=claripy.BVV(music,8);st.globals['audio_rom_bank']=claripy.BVV(8,8);st.globals['audio_saved_bank']=claripy.BVV(8,8);st.globals['stop_sound_called']=claripy.BVV(1,8);st.globals['delay_frame_called']=claripy.BVV(1,8);st.globals['play_music_called']=claripy.BVV(1,8);st.regs.a=claripy.BVV(music,8);st.add_constraints(cond);self.successors.add_successor(st,DONE,claripy.BoolV(True),'Ijk_Boring')
def _assembly(i):
 l=symbol_location(SYMBOLS,'PlayBattleMusic');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q});p.hook(q,Summary(),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for f in FIELDS:s.globals[f]=i[f]
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=5);assert len(m.found)==5
 return [Endpoint(**assembly_registers(x),**{f:x.globals[f] for f in FIELDS},constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_play_battle_music');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for off,f in enumerate(FIELDS,8):s.memory.store(NATIVE_STATE+off,i[f])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)>=3
 return [Endpoint(**native_registers(x,NATIVE_STATE),**{f:x.memory.load(NATIVE_STATE+off,1) for off,f in enumerate(FIELDS,8)},constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_play_battle_music_pathwise_equivalence():
 i=symbolic_registers('battle_music')
 for f in FIELDS:i[f]=claripy.BVS('battle_music_'+f,8)
 assert_pathwise_equivalent(_assembly(i),_native(i),('a','f',*FIELDS))
def test_play_battle_music_exact_linked_body():
 l=symbol_location(SYMBOLS,'PlayBattleMusic');assert linked_bytes(ROM,l,len(EXPECTED_BODY))==EXPECTED_BODY
