from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
from verification.harness.sm83_shims import Sm83AddRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;DONE=0xEFFF
FIELDS=('copy2_a','copy2_f','copy2_b','copy2_c','copy2_d','copy2_e','copy2_h','copy2_l')
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
 copy2_a:claripy.ast.BV;copy2_f:claripy.ast.BV;copy2_b:claripy.ast.BV;copy2_c:claripy.ast.BV;copy2_d:claripy.ast.BV;copy2_e:claripy.ast.BV;copy2_h:claripy.ast.BV;copy2_l:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class NoOp(angr.SimProcedure):
 def run(self)->None:self.jump(self.state.addr+1)
class CallNoOp(angr.SimProcedure):
 def run(self)->None:self.jump(self.state.addr+3)
class LoadBC(angr.SimProcedure):
 def run(self)->None:self.state.regs.b=5;self.state.regs.c=12;self.jump(self.state.addr+3)
class LoadA(angr.SimProcedure):
 def run(self)->None:self.state.regs.a=0xc0;self.jump(self.state.addr+2)
class CopyAToE(angr.SimProcedure):
 def run(self)->None:self.state.regs.e=self.state.regs.a;self.jump(self.state.addr+1)
class IncD(angr.SimProcedure):
 def run(self)->None:self.state.regs.d=self.state.regs.d+1;self.jump(self.state.addr+1)
class SetHBit(angr.SimProcedure):
 def run(self)->None:self.state.regs.h=self.state.regs.h|8;self.jump(self.state.addr+2)
class BranchNC(angr.SimProcedure):
 def __init__(self,taken,fallthrough):super().__init__();self.taken=taken;self.fallthrough=fallthrough
 def run(self)->None:
  self.inhibit_autoret=True;c=(self.state.regs.f&1)==0;self.successors.add_successor(self.state.copy(),self.taken,c,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.fallthrough,claripy.Not(c),'Ijk_Boring')
class CopyVideoSummary(angr.SimProcedure):
 def run(self)->None:
  for r,f in (('a','copy2_a'),('b','copy2_b'),('c','copy2_c'),('d','copy2_d'),('e','copy2_e'),('h','copy2_h'),('l','copy2_l')):setattr(self.state.regs,r,self.state.globals[f])
  self.state.regs.f=sm83_flags_to_z80(self.state.globals['copy2_f']);self.jump(DONE)
def _assembly(i):
 l=symbol_location(SYMBOLS,'LoadPlayerSpriteGraphicsCommon');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q})
 for off in (0,1,8,9):p.hook(q+off,NoOp(),length=1)
 p.hook(q+2,LoadBC(),length=3);p.hook(q+5,CallNoOp(),length=3);p.hook(q+10,LoadA(),length=2);p.hook(q+12,Sm83AddRegister('e',q+13),length=1);p.hook(q+13,CopyAToE(),length=1);p.hook(q+14,BranchNC(q+19,q+16),length=2);p.hook(q+16,IncD(),length=1);p.hook(q+17,SetHBit(),length=2);p.hook(q+19,LoadBC(),length=3);p.hook(q+22,CopyVideoSummary(),length=3)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for f in FIELDS:s.globals[f]=i[f]
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=2);assert len(m.found)==2
 return [Endpoint(**assembly_registers(x),**{f:x.globals[f] for f in FIELDS},constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_load_player_sprite_graphics_common');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for off,f in enumerate(FIELDS,8):s.memory.store(NATIVE_STATE+off,i[f])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1;x=m.deadended[0];return [Endpoint(**native_registers(x,NATIVE_STATE),**{f:x.memory.load(NATIVE_STATE+off,1) for off,f in enumerate(FIELDS,8)},constraints=tuple(x.solver.constraints))]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_load_player_sprite_graphics_common_pathwise_equivalence():
 i=symbolic_registers('lpsg');i['copy2_f']=claripy.Concat(claripy.BVS('lpsg_copy_flags',4),claripy.BVV(0,4))
 for f in ('copy2_a','copy2_b','copy2_c','copy2_d','copy2_e','copy2_h','copy2_l'):i[f]=claripy.BVS('lpsg_'+f,8)
 assert_pathwise_equivalent(_assembly(i),_native(i),('a','f','b','c','d','e','h','l',*FIELDS))
def test_load_player_sprite_graphics_common_exact_body():
 l=symbol_location(SYMBOLS,'LoadPlayerSpriteGraphicsCommon');assert linked_bytes(ROM,l,25)==bytes.fromhex('d5e5010c05cd4818e1d13ec0835f300114cbdc010c05c34818')
