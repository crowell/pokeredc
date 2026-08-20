from __future__ import annotations
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;DONE=0xEFFF
FIELDS=('map_width',)+tuple(f'gate{i}' for i in range(6))+tuple(f'new{i}' for i in range(6))+tuple(f'over{i}' for i in range(6))+tuple(f'offlo{i}' for i in range(6))+tuple(f'offhi{i}' for i in range(6))+('gate_index','backup_index')
EXPECTED_BODY=bytes.fromhex('0607210a6bc3d635')
X=(9,6,6,3,2,2);Y=(3,3,6,8,6,3);BLOCK=(0x54,0x54,0x54,0x5f,0x54,0x54)
class Endpoint:
 def __init__(self,regs,values,constraints):self.__dict__.update(regs);self.__dict__.update(values);self.constraints=tuple(constraints)
class Summary(angr.SimProcedure):
 def run(self)->None:
  paths=[self.state.copy()];stride=claripy.ZeroExt(8,self.state.globals['map_width'])+6
  for slot in range(5,-1,-1):
   nxt=[];flag=self.state.globals[f'gate{slot}']
   for base in paths:
    for opened,cond in ((True,flag!=0),(False,flag==0)):
     st=base.copy();block=0x0e if opened else BLOCK[slot];off=3*stride+3+Y[slot]*stride+X[slot]
     st.globals[f'new{slot}']=claripy.BVV(block,8);st.globals[f'over{slot}']=claripy.BVV(block,8);st.globals[f'offlo{slot}']=off[7:0];st.globals[f'offhi{slot}']=off[15:8];st.globals['gate_index']=claripy.BVV(slot,8);st.globals['backup_index']=claripy.BVV(slot+1,8);st.add_constraints(cond);nxt.append(st)
   paths=nxt
  self.inhibit_autoret=True
  for st in paths:self.successors.add_successor(st,DONE,claripy.BoolV(True),'Ijk_Boring')
def endpoint_asm(s):return Endpoint(assembly_registers(s),{f:s.globals[f] for f in FIELDS},s.solver.constraints)
def endpoint_native(s):
 vals={};offset=8
 for f in FIELDS:
  vals[f]=s.memory.load(NATIVE_STATE+offset,1);offset+=1
 return Endpoint(native_registers(s,NATIVE_STATE),vals,s.solver.constraints)
def _assembly(i):
 l=symbol_location(SYMBOLS,'UpdateCinnabarGymGateTileBlocks');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q});p.hook(q,Summary(),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for f in FIELDS:s.globals[f]=i[f]
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=64);assert len(m.found)==64
 return [endpoint_asm(s) for s in m.found]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_update_cinnabar_gym_gate_tile_blocks');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for off,f in enumerate(FIELDS,8):s.memory.store(NATIVE_STATE+off,i[f])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)>=1
 return [endpoint_native(s) for s in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_update_cinnabar_gym_gate_tile_blocks_pathwise_equivalence():
 i=symbolic_registers('gate');
 for f in FIELDS:i[f]=claripy.BVS('gate_'+f,8)
 assert_pathwise_equivalent(_assembly(i),_native(i),('a','f','b','c','d','e','h','l',*FIELDS))
def test_update_cinnabar_gym_gate_tile_blocks_exact_linked_body():
 l=symbol_location(SYMBOLS,'UpdateCinnabarGymGateTileBlocks');assert linked_bytes(ROM,l,len(EXPECTED_BODY))==EXPECTED_BODY
