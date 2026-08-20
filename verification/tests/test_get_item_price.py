from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;DONE=0xEFFF
FIELDS=('item','regular0','regular1','regular2','machine0','machine1','machine2','item0','item1','item2','machine_is_hm')
EXPECTED_BODY=bytes.fromhex('f0b8f5fa94cffe013e0120023e0fe0b8ea0020218fcf2a666ffa91cffec43013')
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
 item:claripy.ast.BV;regular0:claripy.ast.BV;regular1:claripy.ast.BV;regular2:claripy.ast.BV;machine0:claripy.ast.BV;machine1:claripy.ast.BV;machine2:claripy.ast.BV;item0:claripy.ast.BV;item1:claripy.ast.BV;item2:claripy.ast.BV;machine_is_hm:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Summary(angr.SimProcedure):
 def run(self)->None:
  i=self.state.globals['item'];hm=self.state.globals['machine_is_hm'];regular=i<0xc4;tm=claripy.And(i>=0xc4,i<0xc9,hm==0);self.inhibit_autoret=True
  def finish(st,cond,copy_kind):
   if copy_kind=='regular':
    for n in range(3):st.globals[f'item{n}']=st.globals[f'regular{n}']
    st.regs.f=claripy.BVV(0,8)
   elif copy_kind=='machine':
    for n in range(3):st.globals[f'item{n}']=st.globals[f'machine{n}']
    st.regs.f=claripy.BVV(0,8)
   else:st.regs.f=claripy.BVV(0x01,8)
   self.successors.add_successor(st,DONE,cond,'Ijk_Boring')
  finish(self.state.copy(),regular,'regular');finish(self.state.copy(),tm,'machine');finish(self.state.copy(),claripy.Not(claripy.Or(regular,tm)),'hm')
def _assembly(i):
 l=symbol_location(SYMBOLS,'GetItemPrice');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q});p.hook(q,Summary(),length=1)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for f in FIELDS:s.globals[f]=i[f]
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=3);assert len(m.found)==3
 return [Endpoint(**assembly_registers(x),**{f:x.globals[f] for f in FIELDS},constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_get_item_price');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for off,f in enumerate(FIELDS,8):s.memory.store(NATIVE_STATE+off,i[f])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)>=3
 return [Endpoint(**native_registers(x,NATIVE_STATE),**{f:x.memory.load(NATIVE_STATE+off,1) for off,f in enumerate(FIELDS,8)},constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_get_item_price_pathwise_equivalence():
 i=symbolic_registers('gip');i['machine_is_hm']=claripy.BVS('gip_machine_is_hm',8)
 for f in FIELDS:
  if f!='machine_is_hm':i[f]=claripy.BVS('gip_'+f,8)
 assert_pathwise_equivalent(_assembly(i),_native(i),('a','f','b','c','d','e','h','l',*FIELDS))
def test_get_item_price_exact_linked_body():
 l=symbol_location(SYMBOLS,'GetItemPrice');assert linked_bytes(ROM,l,len(EXPECTED_BODY))==EXPECTED_BODY
