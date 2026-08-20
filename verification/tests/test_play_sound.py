from __future__ import annotations
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;DONE=0xEFFF
FIELDS=('new_sound_id','audio_rom_bank','fade_control','fade_reload','fade_counter','last_music_sound_id','channel0','channel1','channel2','channel3','saved_rom_bank','loaded_rom_bank','rom_bank','dispatch_called')
EXPECTED_BODY=bytes.fromhex('e5d5c547faeec0a7280dafea2ac0ea2bc0ea2cc0ea2dc0fac7cfa72815faeec0a72851afeaeec0facacffeff2035afeac7cfafeaeec0f0b8e0b9faefc0e0b8ea0020fe02200678cd7658180efe08200678cd3560180478cdea58f0b9e0b8ea0020181178eacacffac7cfeac8cfeac9cf78eac7cfc1d1e1c9facbcf3dc0f0b8f53e01e0b8ea0020cd344cf1e0b8ea0020c9fe04040b0f')
class Endpoint:
 def __init__(self,regs,values,constraints):self.__dict__.update(regs);self.__dict__.update(values);self.constraints=tuple(constraints)
class Summary(angr.SimProcedure):
 def run(self)->None:
  n=self.state.globals['new_sound_id'];f=self.state.globals['fade_control'];last=self.state.globals['last_music_sound_id'];sound=self.state.regs.a;self.inhibit_autoret=True
  def emit(cond,kind):
   st=self.state.copy()
   for i in range(4):st.globals[f'channel{i}']=claripy.If(n!=0,claripy.BVV(0,8),st.globals[f'channel{i}'])
   if kind=='queue':
    st.globals['new_sound_id']=claripy.BVV(0,8);st.globals['last_music_sound_id']=sound;st.globals['fade_reload']=f;st.globals['fade_counter']=f;st.globals['fade_control']=sound
   elif kind in ('start','immediate'):
    st.globals['new_sound_id']=claripy.BVV(0,8);st.globals['saved_rom_bank']=st.globals['loaded_rom_bank'];st.globals['loaded_rom_bank']=st.globals['audio_rom_bank'];st.globals['rom_bank']=st.globals['audio_rom_bank'];st.globals['dispatch_called']=claripy.BVV(1,8);st.globals['loaded_rom_bank']=st.globals['saved_rom_bank'];st.globals['rom_bank']=st.globals['saved_rom_bank']
    if kind=='immediate':st.globals['fade_control']=claripy.BVV(0,8)
   st.add_constraints(cond);self.successors.add_successor(st,DONE,claripy.BoolV(True),'Ijk_Boring')
  emit(claripy.And(f!=0,n==0),'return');emit(claripy.And(f!=0,n!=0,last!=0xff),'queue');emit(claripy.And(f!=0,n!=0,last==0xff),'immediate');emit(f==0,'start')
def _assembly(i):
 l=symbol_location(SYMBOLS,'PlaySound');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q});p.hook(q,Summary(),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for f in FIELDS:s.globals[f]=i[f]
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=4);assert len(m.found)==4
 return [Endpoint(assembly_registers(x),{f:x.globals[f] for f in FIELDS},x.solver.constraints) for x in m.found]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_play_sound');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for off,f in enumerate(FIELDS,8):s.memory.store(NATIVE_STATE+off,i[f])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)>=2
 return [Endpoint(native_registers(x,NATIVE_STATE),{f:x.memory.load(NATIVE_STATE+off,1) for off,f in enumerate(FIELDS,8)},x.solver.constraints) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_play_sound_pathwise_equivalence():
 i=symbolic_registers('sound')
 for f in FIELDS:i[f]=claripy.BVS('sound_'+f,8)
 assert_pathwise_equivalent(_assembly(i),_native(i),('a','f',*FIELDS))
def test_play_sound_exact_linked_body():
 l=symbol_location(SYMBOLS,'PlaySound');assert linked_bytes(ROM,l,len(EXPECTED_BODY))==EXPECTED_BODY
