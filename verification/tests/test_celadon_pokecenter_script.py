from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x400000;DONE=0xEFFF
R_SB=0xFF01;H_RX=0xFFAD;R_SC=0xFF02;W_CONTROL=0xCF0C;W_WAIT=0xCC3C
EXPECTED=bytes.fromhex('cdfa22c33c3c')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;sb:claripy.ast.BV;rx:claripy.ast.BV;sc:claripy.ast.BV;control:claripy.ast.BV;wait:claripy.ast.BV;se:claripy.ast.BV;at:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class SerialBoundary(angr.SimProcedure):
 """Proven serial boundary at the called entry: snapshot registers plus the
 three hardware bytes, apply the shared arbitrary proven transition, continue
 after the replaced CALL."""
 def __init__(self,next_address:int)->None:
  super().__init__();self._next=next_address
 def run(self):
  r=assembly_registers(self.state);m=self.state.memory
  self.state.globals['se']=claripy.Concat(*(r[x] for x in REGISTERS),m.load(R_SB,1),m.load(H_RX,1),m.load(R_SC,1))
  for x in REGISTERS:
   v=self.state.globals[f'se_out_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  m.store(R_SB,self.state.globals['se_out_sb']);m.store(H_RX,self.state.globals['se_out_rx']);m.store(R_SC,self.state.globals['se_out_sc'])
  self.jump(self._next)
class ATBDBoundary(angr.SimProcedure):
 """Proven EnableAutoTextBoxDrawing boundary at the tail target: snapshot the
 hand-off state, apply the shared arbitrary proven transition, stop."""
 def run(self):
  r=assembly_registers(self.state);m=self.state.memory
  self.state.globals['at']=claripy.Concat(*(r[x] for x in REGISTERS),m.load(W_CONTROL,1),m.load(W_WAIT,1))
  for x in REGISTERS:
   v=self.state.globals[f'at_out_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  m.store(W_CONTROL,self.state.globals['at_out_control']);m.store(W_WAIT,self.state.globals['at_out_wait'])
  self.jump(DONE)
def inputs(p):
 v=symbolic_registers(p)
 for pre in ('se','at'):
  for x in REGISTERS:v[f'{pre}_out_{x}']=claripy.Concat(claripy.BVS(f'{p}_{pre}_out_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(f'{p}_{pre}_out_{x}',8)
 v['se_out_sb']=claripy.BVS(f'{p}_se_out_sb',8);v['se_out_rx']=claripy.BVS(f'{p}_se_out_rx',8);v['se_out_sc']=claripy.BVS(f'{p}_se_out_sc',8)
 v['at_out_control']=claripy.BVS(f'{p}_at_out_control',8);v['at_out_wait']=claripy.BVS(f'{p}_at_out_wait',8)
 v['sb_in']=claripy.BVS(f'{p}_sb_in',8);v['rx_in']=claripy.BVS(f'{p}_rx_in',8);v['sc_in']=claripy.BVS(f'{p}_sc_in',8)
 v['control_in']=claripy.BVS(f'{p}_control_in',8);v['wait_in']=claripy.BVS(f'{p}_wait_in',8)
 return v
def setup(s,v):
 s.globals['se']=claripy.BVV(0,11*8);s.globals['at']=claripy.BVV(0,10*8)
 for key,val in v.items():
  if key.startswith(('se_out_','at_out_')):s.globals[key]=val
def store_memory(s,v,base=0):
 s.memory.store(base+R_SB,v['sb_in']);s.memory.store(base+H_RX,v['rx_in']);s.memory.store(base+R_SC,v['sc_in'])
 s.memory.store(base+W_CONTROL,v['control_in']);s.memory.store(base+W_WAIT,v['wait_in'])
def assembly(v):
 l=symbol_location(SYMS,'CeladonPokecenter_Script');t=symbol_location(SYMS,'Serial_TryEstablishingExternallyClockedConnection');a=symbol_location(SYMS,'EnableAutoTextBoxDrawing')
 assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+0,SerialBoundary(b+3),length=3)
 p.hook(a.address,ATBDBoundary())
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v);store_memory(s,v)
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=8);assert not m.errored and len(m.found)==1
 return [E(**assembly_registers(x),sb=x.memory.load(R_SB,1),rx=x.memory.load(H_RX,1),sc=x.memory.load(R_SC,1),control=x.memory.load(W_CONTROL,1),wait=x.memory.load(W_WAIT,1),se=x.globals['se'],at=x.globals['at'],constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_celadon_pokecenter_script');se=p.loader.find_symbol('port_serial_try_establishing_externally_clocked_connection');at=p.loader.find_symbol('port_enable_auto_text_box_drawing');assert f and se and at
 p.hook(se.rebased_addr,NSE());p.hook(at.rebased_addr,NATB())
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v);store_memory(s,v,NM)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1
 return [E(**native_registers(x,NS),sb=x.memory.load(NM+R_SB,1),rx=x.memory.load(NM+H_RX,1),sc=x.memory.load(NM+R_SC,1),control=x.memory.load(NM+W_CONTROL,1),wait=x.memory.load(NM+W_WAIT,1),se=x.globals['se'],at=x.globals['at'],constraints=tuple(x.solver.constraints)) for x in m.deadended]
class NSE(angr.SimProcedure):
 """11-byte black_screen_state arrives via rdi; explicit RET."""
 def run(self):
  s=self.state.regs.rdi;mm=self.state.memory
  self.state.globals['se']=claripy.Concat(mm.load(s,8),mm.load(s+8,1),mm.load(s+9,1),mm.load(s+10,1))
  mm.store(s,claripy.Concat(*(self.state.globals[f'se_out_{x}'] for x in REGISTERS)))
  mm.store(s+8,self.state.globals['se_out_sb']);mm.store(s+9,self.state.globals['se_out_rx']);mm.store(s+10,self.state.globals['se_out_sc'])
  ra=mm.load(self.state.regs.sp,8,endness='Iend_LE');self.state.regs.sp=self.state.regs.sp+8;self.jump(ra)
class NATB(angr.SimProcedure):
 """10-byte auto_text_box_state arrives via rdi; explicit RET."""
 def run(self):
  s=self.state.regs.rdi;mm=self.state.memory
  self.state.globals['at']=claripy.Concat(mm.load(s,8),mm.load(s+8,1),mm.load(s+9,1))
  mm.store(s,claripy.Concat(*(self.state.globals[f'at_out_{x}'] for x in REGISTERS)))
  mm.store(s+8,self.state.globals['at_out_control']);mm.store(s+9,self.state.globals['at_out_wait'])
  ra=mm.load(self.state.regs.sp,8,endness='Iend_LE');self.state.regs.sp=self.state.regs.sp+8;self.jump(ra)
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_celadon_pokecenter_script_pathwise_equivalence():
 v=inputs('celadon_pokecenter_script');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'sb','rx','sc','control','wait','se','at'))
