from __future__ import annotations
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;DONE=0xEFFF
FIELDS=('letter_printing_delay_flags','enemy_mon_species2','trainer_class','ai_count','enemy_mon_party_pos','is_in_battle','start_tile_id','init_battle_variables_called','init_wild_battle_called','trainer_information_called','init_battle_common_called')
EXPECTED_BODY=bytes.fromhex('fa5dd3f52158d37ef5cb8e21af650614cdd635fad8cfd6c8da8b6fea31d0cd663521535c060ecdd635cd326ccd4b70afead8cfe0e13deadfcc21acc33e01cd6d3e3effeae8cf3e02ea57d0c3eb6f')
class Endpoint:
 def __init__(self,regs,values,constraints):self.__dict__.update(regs);self.__dict__.update(values);self.constraints=tuple(constraints)
class Summary(angr.SimProcedure):
 def run(self)->None:
  e=self.state.globals['enemy_mon_species2'];self.inhibit_autoret=True
  for cond,wild in ((e<200,True),(e>=200,False)):
   st=self.state.copy();st.globals['letter_printing_delay_flags']=st.globals['letter_printing_delay_flags']&0xfd;st.globals['init_battle_variables_called']=claripy.BVV(1,8)
   if wild:
    st.globals['init_wild_battle_called']=claripy.BVV(1,8);st.globals['is_in_battle']=claripy.BVV(1,8)
   else:
    st.globals['trainer_class']=e-200;st.globals['trainer_information_called']=claripy.BVV(1,8);st.globals['enemy_mon_species2']=claripy.BVV(0,8);st.globals['start_tile_id']=claripy.BVV(0,8);st.globals['ai_count']=claripy.BVV(0xff,8);st.globals['enemy_mon_party_pos']=claripy.BVV(0xff,8);st.globals['is_in_battle']=claripy.BVV(2,8);st.globals['init_battle_common_called']=claripy.BVV(1,8)
   st.add_constraints(cond);self.successors.add_successor(st,DONE,claripy.BoolV(True),'Ijk_Boring')
def _assembly(i):
 l=symbol_location(SYMBOLS,'InitBattleCommon');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q});p.hook(q,Summary(),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for f in FIELDS:s.globals[f]=i[f]
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=2);assert len(m.found)==2
 return [Endpoint(assembly_registers(x),{f:x.globals[f] for f in FIELDS},x.solver.constraints) for x in m.found]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_init_battle_common');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for off,f in enumerate(FIELDS,8):s.memory.store(NATIVE_STATE+off,i[f])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)>=2
 return [Endpoint(native_registers(x,NATIVE_STATE),{f:x.memory.load(NATIVE_STATE+off,1) for off,f in enumerate(FIELDS,8)},x.solver.constraints) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_init_battle_common_pathwise_equivalence():
 i=symbolic_registers('init_battle');
 for f in FIELDS:i[f]=claripy.BVS('init_battle_'+f,8)
 assert_pathwise_equivalent(_assembly(i),_native(i),('a','f','b','c','d','e','h','l',*FIELDS))
def test_init_battle_common_exact_linked_body():
 l=symbol_location(SYMBOLS,'InitBattleCommon');assert linked_bytes(ROM,l,len(EXPECTED_BODY))==EXPECTED_BODY
