from __future__ import annotations
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;DONE=0xEFFF
FIELDS=('current_item','action_result','item_handler_address','dispatched_hl','tm_hm_dispatch')
EXPECTED_BODY=bytes.fromhex('3e01ea6acdfa91cffec4d2796421e1553d874f0600092a666fe9')
class Endpoint:
 def __init__(self,regs,values,constraints):self.__dict__.update(regs);self.__dict__.update(values);self.constraints=tuple(constraints)
class Summary(angr.SimProcedure):
 def run(self)->None:
  item=self.state.globals['current_item'];handler=self.state.globals['item_handler_address'];cp=claripy.BVV(0x40,8)|claripy.If(item==0xc4,claripy.BVV(0x80,8),claripy.BVV(0,8))|claripy.If(claripy.ULT(item&0xf,4),claripy.BVV(0x20,8),claripy.BVV(0,8))|claripy.If(claripy.ULT(item,0xc4),claripy.BVV(0x10,8),claripy.BVV(0,8));self.inhibit_autoret=True
  for cond,tm in ((claripy.ULT(item,0xc4),False),(claripy.UGE(item,0xc4),True)):
   st=self.state.copy();st.regs.a=item;st.regs.f=sm83_flags_to_z80(cp);st.globals['action_result']=claripy.BVV(1,8);st.globals['tm_hm_dispatch']=claripy.BVV(1 if tm else 0,8);st.globals['dispatched_hl']=claripy.If(claripy.BoolV(tm),claripy.BVV(0x6479,16),handler);st.add_constraints(cond);self.successors.add_successor(st,DONE,claripy.BoolV(True),'Ijk_Boring')
def _assembly(i):
 l=symbol_location(SYMBOLS,'UseItem_');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q});p.hook(q,Summary(),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for f in FIELDS:s.globals[f]=i[f]
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=2);assert len(m.found)==2
 return [Endpoint(assembly_registers(x),{f:x.globals[f] for f in FIELDS},x.solver.constraints) for x in m.found]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_use_item_');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i['current_item']);s.memory.store(NATIVE_STATE+9,i['action_result']);s.memory.store(NATIVE_STATE+10,i['item_handler_address'],endness='Iend_LE');s.memory.store(NATIVE_STATE+12,i['dispatched_hl'],endness='Iend_LE');s.memory.store(NATIVE_STATE+14,i['tm_hm_dispatch'])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)>=2
 def val(x,off,w=1):return x.memory.load(NATIVE_STATE+off,w,endness='Iend_LE')
 return [Endpoint(native_registers(x,NATIVE_STATE),{'current_item':val(x,8),'action_result':val(x,9),'item_handler_address':val(x,10,2),'dispatched_hl':val(x,12,2),'tm_hm_dispatch':val(x,14)},x.solver.constraints) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_use_item_dispatch_pathwise_equivalence():
 i=symbolic_registers('use_dispatch');i['current_item']=claripy.BVS('use_dispatch_item',8);i['action_result']=claripy.BVS('use_dispatch_action',8);i['item_handler_address']=claripy.BVS('use_dispatch_handler',16);i['dispatched_hl']=claripy.BVS('use_dispatch_dispatched',16);i['tm_hm_dispatch']=claripy.BVS('use_dispatch_tm',8)
 assert_pathwise_equivalent(_assembly(i),_native(i),('a','f',*FIELDS))
def test_use_item_dispatch_exact_linked_body():
 l=symbol_location(SYMBOLS,'UseItem_');assert linked_bytes(ROM,l,len(EXPECTED_BODY))==EXPECTED_BODY
