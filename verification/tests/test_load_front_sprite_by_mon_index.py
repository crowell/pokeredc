from __future__ import annotations
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;DONE=0xEFFF
FIELDS=('saved_pokedex_num','dex_number','pokedex_num','cur_party_species','start_tile_id','sprite_flipped','load_front_sprite_called','copy_pic_called','loaded_rom_bank','saved_rom_bank','rom_bank')
EXPECTED_BODY=bytes.fromhex('e5fa1ed1f5fa91cfea1ed13e3acd6d3e211ed17ec170a7e12804fe9838063e01ea91cfc9e5110090cd6516e1f0b8f53e0fe0b8ea0020afe0e1cdd070afeaaad0f1e0b8ea0020c9')
class Endpoint:
 def __init__(self,regs,values,constraints):self.__dict__.update(regs);self.__dict__.update(values);self.constraints=tuple(constraints)
class Summary(angr.SimProcedure):
 def run(self)->None:
  dex=self.state.globals['dex_number'];self.inhibit_autoret=True
  for cond,kind in ((dex==0,'zero'),(claripy.And(claripy.UGE(dex,1),claripy.ULE(dex,151)),'valid'),(claripy.UGE(dex,152),'high')):
   st=self.state.copy();st.globals['pokedex_num']=st.globals['saved_pokedex_num']
   if kind=='zero':
    st.regs.a=claripy.BVV(1,8);st.regs.f=claripy.BVV(0x50,8);st.globals['cur_party_species']=claripy.BVV(1,8)
   elif kind=='valid':
    st.regs.a=claripy.BVV(0,8);st.regs.f=claripy.BVV(0x40,8);st.globals['start_tile_id']=claripy.BVV(0,8);st.globals['sprite_flipped']=claripy.BVV(0,8);st.globals['load_front_sprite_called']=claripy.BVV(1,8);st.globals['copy_pic_called']=claripy.BVV(1,8)
   else:
    cp=claripy.BVV(0x02,8)|claripy.If(dex==152,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If(claripy.ULT((dex&0xf),8),claripy.BVV(0x10,8),claripy.BVV(0,8));st.regs.a=claripy.BVV(1,8);st.regs.f=cp;st.globals['cur_party_species']=claripy.BVV(1,8)
   st.add_constraints(cond);self.successors.add_successor(st,DONE,claripy.BoolV(True),'Ijk_Boring')
def _assembly(i):
 l=symbol_location(SYMBOLS,'LoadFrontSpriteByMonIndex');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q});p.hook(q,Summary(),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for f in FIELDS:s.globals[f]=i[f]
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=3);assert len(m.found)==3
 return [Endpoint(assembly_registers(x),{f:x.globals[f] for f in FIELDS},x.solver.constraints) for x in m.found]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_load_front_sprite_by_mon_index');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for off,f in enumerate(FIELDS,8):s.memory.store(NATIVE_STATE+off,i[f])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)>=3
 return [Endpoint(native_registers(x,NATIVE_STATE),{f:x.memory.load(NATIVE_STATE+off,1) for off,f in enumerate(FIELDS,8)},x.solver.constraints) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_load_front_sprite_by_mon_index_pathwise_equivalence():
 i=symbolic_registers('front');
 for f in FIELDS:i[f]=claripy.BVS('front_'+f,8)
 assert_pathwise_equivalent(_assembly(i),_native(i),('a','f',*FIELDS))
def test_load_front_sprite_by_mon_index_exact_linked_body():
 l=symbol_location(SYMBOLS,'LoadFrontSpriteByMonIndex');assert linked_bytes(ROM,l,len(EXPECTED_BODY))==EXPECTED_BODY
