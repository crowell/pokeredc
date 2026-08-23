from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x400000;DONE=0xEFFF
EXPECTED=bytes.fromhex('3e0bc3f717')
H_BANK=0xFFB8;R_ROMB=0x2000
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;hb:claripy.ast.BV;rb:claripy.ast.BV;call:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class FC2Tail(angr.SimProcedure):
 """Proven FarCopyData2 boundary at the tail target: snapshot registers
 (A = requested bank) plus the saved/loaded bank bytes, apply the shared
 arbitrary proven transition (registers with bank+AF restoration, bank
 bytes), stop. The copied RAM region belongs to the callee's own proof."""
 def run(self):
  r=assembly_registers(self.state);m=self.state.memory
  self.state.globals['call']=claripy.Concat(*(r[x] for x in REGISTERS),m.load(H_BANK,1),m.load(R_ROMB,1))
  for x in REGISTERS:
   v=self.state.globals[f'fc_out_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  m.store(H_BANK,self.state.globals['fc_out_hb']);m.store(R_ROMB,self.state.globals['fc_out_rb'])
  self.jump(DONE)
class NFC(angr.SimProcedure):
 def run(self,s):
  mm=self.state.memory
  self.state.globals['call']=claripy.Concat(mm.load(s,8),mm.load(s+9,1),mm.load(s+10,1))
  mm.store(s,claripy.Concat(*(self.state.globals[f'fc_out_{x}'] for x in REGISTERS)))
  mm.store(s+9,self.state.globals['fc_out_hb']);mm.store(s+10,self.state.globals['fc_out_rb'])
  ra=mm.load(self.state.regs.sp,8,endness='Iend_LE');self.state.regs.sp=self.state.regs.sp+8;self.jump(ra)
def inputs(p):
 v=symbolic_registers(p)
 for x in REGISTERS:v[f'fc_out_{x}']=claripy.Concat(claripy.BVS(f'{p}_fc_out_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(f'{p}_fc_out_{x}',8)
 v['fc_out_hb']=claripy.BVS(f'{p}_fc_out_hb',8);v['fc_out_rb']=claripy.BVS(f'{p}_fc_out_rb',8)
 v['hb_in']=claripy.BVS(f'{p}_hb_in',8);v['rb_in']=claripy.BVS(f'{p}_rb_in',8)
 return v
def setup(s,v):
 s.globals['call']=claripy.BVV(0,10*8)
 for key,val in v.items():
  if key.startswith(('fc_out_','hb_','rb_')):s.globals[key]=val
def assembly(v):
 l=symbol_location(SYMS,'TrainerInfo_FarCopyData');t=symbol_location(SYMS,'FarCopyData2');assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(t.address,FC2Tail())
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v);s.memory.store(H_BANK,v['hb_in']);s.memory.store(R_ROMB,v['rb_in'])
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=8);assert not m.errored and len(m.found)==1
 return [E(**assembly_registers(x),hb=x.memory.load(H_BANK,1),rb=x.memory.load(R_ROMB,1),call=x.globals['call'],constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_trainer_info_far_copy_data');t=p.loader.find_symbol('port_far_copy_data2');assert f and t
 p.hook(t.rebased_addr,NFC())
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v);s.memory.store(NM+H_BANK,v['hb_in']);s.memory.store(NM+R_ROMB,v['rb_in'])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1
 return [E(**native_registers(x,NS),hb=x.memory.load(NM+H_BANK,1),rb=x.memory.load(NM+R_ROMB,1),call=x.globals['call'],constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_trainer_info_far_copy_data_pathwise_equivalence():
 v=inputs('trainer_info_far_copy_data');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'hb','rb','call'))
