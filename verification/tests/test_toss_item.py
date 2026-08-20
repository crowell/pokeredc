from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;DONE=0xEFFF
FIELDS=('item','is_hm','is_key_item','menu_exit_method','named_object_index','text_box_id','removed','which_item','item_quantity')
EXPECTED_BODY=bytes.fromhex('f0b8f53e03e0b8ea0020cdf166d17ae0b8ea0020c9')
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
 item:claripy.ast.BV;is_hm:claripy.ast.BV;is_key_item:claripy.ast.BV;menu_exit_method:claripy.ast.BV;named_object_index:claripy.ast.BV;text_box_id:claripy.ast.BV;removed:claripy.ast.BV;which_item:claripy.ast.BV;item_quantity:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Summary(angr.SimProcedure):
 def run(self)->None:
  hm=self.state.globals['is_hm']!=0;key=self.state.globals['is_key_item']!=0;menu=self.state.globals['menu_exit_method']==2;blocked=claripy.Or(hm,key);self.inhibit_autoret=True
  def finish(cond,kind):
   st=self.state.copy()
   if kind=='yes':
    st.globals['named_object_index']=st.globals['item'];st.globals['text_box_id']=claripy.BVV(0x14,8);st.globals['removed']=claripy.BVV(1,8);st.regs.f=claripy.BVV(0,8)
   elif kind=='no':
    st.globals['named_object_index']=st.globals['item'];st.globals['text_box_id']=claripy.BVV(0x14,8);st.regs.f=claripy.BVV(1,8)
   else:st.regs.f=claripy.BVV(1,8)
   self.successors.add_successor(st,DONE,cond,'Ijk_Boring')
  finish(hm,'blocked');finish(claripy.And(claripy.Not(hm),key),'blocked');finish(claripy.And(claripy.Not(blocked),menu),'no');finish(claripy.And(claripy.Not(blocked),claripy.Not(menu)),'yes')
def _assembly(i):
 l=symbol_location(SYMBOLS,'TossItem');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q});p.hook(q,Summary(),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for f in FIELDS:s.globals[f]=i[f]
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=4);assert len(m.found)==4
 return [Endpoint(**assembly_registers(x),**{f:x.globals[f] for f in FIELDS},constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_toss_item');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for off,f in enumerate(FIELDS,8):s.memory.store(NATIVE_STATE+off,i[f])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)>=4
 return [Endpoint(**native_registers(x,NATIVE_STATE),**{f:x.memory.load(NATIVE_STATE+off,1) for off,f in enumerate(FIELDS,8)},constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_toss_item_pathwise_equivalence():
 i=symbolic_registers('toss')
 for f in FIELDS:i[f]=claripy.BVS('toss_'+f,8)
 assert_pathwise_equivalent(_assembly(i),_native(i),('a','f','b','c','d','e','h','l',*FIELDS))
def test_toss_item_exact_linked_body():
 l=symbol_location(SYMBOLS,'TossItem');assert linked_bytes(ROM,l,len(EXPECTED_BODY))==EXPECTED_BODY
