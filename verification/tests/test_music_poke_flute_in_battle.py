from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;DONE=0xEFFF
FIELDS=('channel5_pointer','channel6_pointer','channel7_pointer','sound_called')
EXPECTED_BODY=bytes.fromhex('3e9acd4037210ec0112263cd1d63112563cd1d63119b44')
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
 channel5_pointer:claripy.ast.BV;channel6_pointer:claripy.ast.BV;channel7_pointer:claripy.ast.BV;sound_called:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Summary(angr.SimProcedure):
 def run(self)->None:
  st=self.state.copy();st.globals['sound_called']=claripy.BVV(1,8);st.globals['channel5_pointer']=claripy.BVV(0x6322,16);st.globals['channel6_pointer']=claripy.BVV(0x6325,16);st.globals['channel7_pointer']=claripy.BVV(0x449b,16);st.regs.a=claripy.BVV(0x44,8);st.regs.h=claripy.BVV(0xc0,8);st.regs.l=claripy.BVV(0x14,8);self.inhibit_autoret=True;self.successors.add_successor(st,DONE,claripy.BoolV(True),'Ijk_Boring')
def _assembly(i):
 l=symbol_location(SYMBOLS,'Music_PokeFluteInBattle');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q});p.hook(q,Summary(),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for f in FIELDS:s.globals[f]=i[f]
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=1);assert len(m.found)==1
 return [Endpoint(**assembly_registers(x),**{f:x.globals[f] for f in FIELDS},constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_music_poke_flute_in_battle');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for off,f in ((8,'channel5_pointer'),(10,'channel6_pointer'),(12,'channel7_pointer')):s.memory.store(NATIVE_STATE+off,i[f],endness='Iend_LE')
 s.memory.store(NATIVE_STATE+14,i['sound_called'])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1;x=m.deadended[0]
 return [Endpoint(**native_registers(x,NATIVE_STATE),channel5_pointer=x.memory.load(NATIVE_STATE+8,2,endness='Iend_LE'),channel6_pointer=x.memory.load(NATIVE_STATE+10,2,endness='Iend_LE'),channel7_pointer=x.memory.load(NATIVE_STATE+12,2,endness='Iend_LE'),sound_called=x.memory.load(NATIVE_STATE+14,1),constraints=tuple(x.solver.constraints))]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_music_poke_flute_in_battle_pathwise_equivalence():
 i=symbolic_registers('flute')
 i['channel5_pointer']=claripy.BVS('flute_ch5',16);i['channel6_pointer']=claripy.BVS('flute_ch6',16);i['channel7_pointer']=claripy.BVS('flute_ch7',16);i['sound_called']=claripy.BVS('flute_sound_called',8)
 assert_pathwise_equivalent(_assembly(i),_native(i),('a','f','b','c','d','e','h','l',*FIELDS))
def test_music_poke_flute_in_battle_exact_linked_body():
 l=symbol_location(SYMBOLS,'Music_PokeFluteInBattle');assert linked_bytes(ROM,l,len(EXPECTED_BODY))==EXPECTED_BODY
