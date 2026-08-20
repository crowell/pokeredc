from __future__ import annotations
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;DONE=0xEFFF
FIELDS=('party_count','box_count','added_to_party','do_not_wait','enemy_battle_status3','enemy_mon_species2','current_box_num','cur_party_species','string0','string1','string2','add_party_mon_called','send_to_box_called')
EXPECTED_BODY=bytes.fromhex('cd3c3cafead3ccfa63d1fe06384efa80dafe14303fafea69d0fa91cfead8cf21016b060fcdd635cd117e21a4670603cdd635214bcffaa0d5e67ffe093809d60936f723c6f61802')
class Endpoint:
 def __init__(self,regs,values,constraints):self.__dict__.update(regs);self.__dict__.update(values);self.constraints=tuple(constraints)
class Summary(angr.SimProcedure):
 def run(self)->None:
  party=self.state.globals['party_count'];box=self.state.globals['box_count'];curbox=self.state.globals['current_box_num'];species=self.state.globals['cur_party_species'];self.inhibit_autoret=True
  st=self.state.copy();st.globals['added_to_party']=claripy.BVV(1,8);st.globals['do_not_wait']=claripy.BVV(1,8);st.globals['add_party_mon_called']=claripy.BVV(1,8);st.regs.f=claripy.BVV(1,8);st.add_constraints(claripy.ULT(party,6));self.successors.add_successor(st,DONE,claripy.BoolV(True),'Ijk_Boring')
  st=self.state.copy();st.globals['added_to_party']=claripy.BVV(0,8);st.regs.f=claripy.BVV(0,8);st.add_constraints(claripy.And(claripy.UGE(party,6),claripy.UGE(box,20)));self.successors.add_successor(st,DONE,claripy.BoolV(True),'Ijk_Boring')
  st=self.state.copy();b=curbox&0x7f;ge=claripy.UGE(b,9);st.globals['added_to_party']=claripy.BVV(0,8);st.globals['enemy_battle_status3']=claripy.BVV(0,8);st.globals['enemy_mon_species2']=species;st.globals['send_to_box_called']=claripy.BVV(1,8);st.globals['string0']=claripy.If(ge,claripy.BVV(ord('1'),8),b+ord('1'));st.globals['string1']=claripy.If(ge,b-9+ord('0'),claripy.BVV(ord('@'),8));st.globals['string2']=claripy.If(ge,claripy.BVV(ord('@'),8),claripy.BVV(0,8));st.regs.f=claripy.BVV(1,8);st.add_constraints(claripy.And(claripy.UGE(party,6),claripy.ULT(box,20)));self.successors.add_successor(st,DONE,claripy.BoolV(True),'Ijk_Boring')
def _assembly(i):
 l=symbol_location(SYMBOLS,'_GivePokemon');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q});p.hook(q,Summary(),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for f in FIELDS:s.globals[f]=i[f]
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=3);assert len(m.found)==3
 return [Endpoint(assembly_registers(x),{f:x.globals[f] for f in FIELDS},x.solver.constraints) for x in m.found]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_give_pokemon');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for off,f in enumerate(FIELDS,8):s.memory.store(NATIVE_STATE+off,i[f])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)>=3
 return [Endpoint(native_registers(x,NATIVE_STATE),{f:x.memory.load(NATIVE_STATE+off,1) for off,f in enumerate(FIELDS,8)},x.solver.constraints) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_give_pokemon_pathwise_equivalence():
 i=symbolic_registers('give');
 for f in FIELDS:i[f]=claripy.BVS('give_'+f,8)
 assert_pathwise_equivalent(_assembly(i),_native(i),('a','f',*FIELDS))
def test_give_pokemon_exact_linked_body():
 l=symbol_location(SYMBOLS,'_GivePokemon');assert linked_bytes(ROM,l,len(EXPECTED_BODY))==EXPECTED_BODY
