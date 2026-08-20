from __future__ import annotations
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;DONE=0xEFFF
FIELDS=('surf_state','map_music_sound','map_music_bank','audio_rom_bank','audio_saved_bank','last_music_sound','new_sound_id','fade_control','play_sound_called')
EXPECTED_BODY=bytes.fromhex('fa00d7a72819fe0228043ed218023ed6477aa73e1f2003eaefc0eaf0c01809fa5bd347cd85233805facacfb8c879eac7cf78eacacfeaeec0c3b123faefc047fe022005210351180cfe08200521795818032177510e06c5e5cdd635e1c10d20f6c9fa5cd35ffaefc0bb2005eaf0c0a7c979a77b2003eaefc0eaf0c037c9')
class Endpoint:
 def __init__(self,regs,values,constraints):self.__dict__.update(regs);self.__dict__.update(values);self.constraints=tuple(constraints)
class Summary(angr.SimProcedure):
 def run(self)->None:
  s=self.state;surf=s.globals['surf_state'];audio=s.globals['audio_rom_bank'];mapbank=s.globals['map_music_bank'];mapsound=s.globals['map_music_sound'];last=s.globals['last_music_sound'];c=s.regs.c;d=s.regs.d;self.inhibit_autoret=True
  def emit(cond,music,save,update_audio,play):
   st=s.copy()
   if update_audio:st.globals['audio_rom_bank']=mapbank if save==0 else claripy.BVV(0x1f,8)
   st.globals['audio_saved_bank']=mapbank if save==0 else claripy.BVV(0x1f,8)
   if play:
    st.globals['fade_control']=c;st.globals['last_music_sound']=music;st.globals['new_sound_id']=music;st.globals['play_sound_called']=claripy.BVV(1,8);st.regs.a=music
   st.add_constraints(cond);self.successors.add_successor(st,DONE,claripy.BoolV(True),'Ijk_Boring')
  walk=surf==0;diff=audio!=mapbank;same=audio==mapbank
  emit(claripy.And(walk,diff,c==0),mapsound,0,True,True);emit(claripy.And(walk,diff,c!=0),mapsound,0,False,True);emit(claripy.And(walk,same,last==mapsound),mapsound,0,False,False);emit(claripy.And(walk,same,last!=mapsound),mapsound,0,False,True)
  for surfcond,music in ((claripy.And(surf!=0,surf!=2),0xd2),(surf==2,0xd6)):
   emit(claripy.And(surfcond,d==0,last==music),claripy.BVV(music,8),1,True,False);emit(claripy.And(surfcond,d==0,last!=music),claripy.BVV(music,8),1,True,True);emit(claripy.And(surfcond,d!=0,last==music),claripy.BVV(music,8),1,False,False);emit(claripy.And(surfcond,d!=0,last!=music),claripy.BVV(music,8),1,False,True)
def _assembly(i):
 l=symbol_location(SYMBOLS,'PlayDefaultMusicCommon');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q});p.hook(q,Summary(),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for f in FIELDS:s.globals[f]=i[f]
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=12);assert len(m.found)==12
 return [Endpoint(assembly_registers(x),{f:x.globals[f] for f in FIELDS},x.solver.constraints) for x in m.found]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_play_default_music_common');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for off,f in enumerate(FIELDS,8):s.memory.store(NATIVE_STATE+off,i[f])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)>=4
 return [Endpoint(native_registers(x,NATIVE_STATE),{f:x.memory.load(NATIVE_STATE+off,1) for off,f in enumerate(FIELDS,8)},x.solver.constraints) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_play_default_music_common_pathwise_equivalence():
 i=symbolic_registers('default_music')
 for f in FIELDS:i[f]=claripy.BVS('default_music_'+f,8)
 assert_pathwise_equivalent(_assembly(i),_native(i),('a','f',*FIELDS))
def test_play_default_music_common_exact_linked_body():
 l=symbol_location(SYMBOLS,'PlayDefaultMusicCommon');assert linked_bytes(ROM,l,len(EXPECTED_BODY))==EXPECTED_BODY
