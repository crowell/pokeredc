from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;DONE=0xEFFF
FIELDS=('channel1_pointer','sound_id','audio_rom_bank','audio_saved_bank','fade_out_control','play_music_called')
EXPECTED_BODY=bytes.fromhex('0e023edecda1232106c0111971c3605b')
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
 channel1_pointer:claripy.ast.BV;sound_id:claripy.ast.BV;audio_rom_bank:claripy.ast.BV;audio_saved_bank:claripy.ast.BV;fade_out_control:claripy.ast.BV;play_music_called:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Summary(angr.SimProcedure):
 def run(self)->None:
  st=self.state.copy();st.regs.c=claripy.BVV(2,8);st.regs.a=claripy.BVV(0xde,8);st.regs.h=claripy.BVV(0xc0,8);st.regs.l=claripy.BVV(8,8);st.globals['channel1_pointer']=claripy.BVV(0x7119,16);st.globals['sound_id']=claripy.BVV(0xde,8);st.globals['audio_rom_bank']=claripy.BVV(2,8);st.globals['audio_saved_bank']=claripy.BVV(2,8);st.globals['fade_out_control']=claripy.BVV(0,8);st.globals['play_music_called']=claripy.BVV(1,8);self.inhibit_autoret=True;self.successors.add_successor(st,DONE,claripy.BoolV(True),'Ijk_Boring')
def _assembly(i):
 l=symbol_location(SYMBOLS,'Music_RivalAlternateTempo');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q});p.hook(q,Summary(),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for f in FIELDS:s.globals[f]=i[f]
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=1);assert len(m.found)==1
 return [Endpoint(**assembly_registers(x),**{f:x.globals[f] for f in FIELDS},constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_music_rival_alternate_tempo');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i['channel1_pointer'],endness='Iend_LE')
 for off,f in ((10,'sound_id'),(11,'audio_rom_bank'),(12,'audio_saved_bank'),(13,'fade_out_control'),(14,'play_music_called')):s.memory.store(NATIVE_STATE+off,i[f])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1;x=m.deadended[0]
 return [Endpoint(**native_registers(x,NATIVE_STATE),channel1_pointer=x.memory.load(NATIVE_STATE+8,2,endness='Iend_LE'),**{f:x.memory.load(NATIVE_STATE+off,1) for off,f in ((10,'sound_id'),(11,'audio_rom_bank'),(12,'audio_saved_bank'),(13,'fade_out_control'),(14,'play_music_called'))},constraints=tuple(x.solver.constraints))]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_music_rival_alternate_tempo_pathwise_equivalence():
 i=symbolic_registers('rival_tempo');i['channel1_pointer']=claripy.BVS('rival_tempo_ch1',16)
 for f in FIELDS[1:]:i[f]=claripy.BVS('rival_tempo_'+f,8)
 assert_pathwise_equivalent(_assembly(i),_native(i),('a','f','b','c','d','e','h','l',*FIELDS))
def test_music_rival_alternate_tempo_exact_linked_body():
 l=symbol_location(SYMBOLS,'Music_RivalAlternateTempo');assert linked_bytes(ROM,l,len(EXPECTED_BODY))==EXPECTED_BODY
