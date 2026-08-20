from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate

ROOT=Path(__file__).resolve().parents[2]
NATIVE_ELF=ROOT/"verification/build/ports.elf"; ROM=ROOT/"pokered.gbc"; SYMBOLS=ROOT/"pokered.sym"; NATIVE_STATE=0x100000; DONE=0xEFFF
FIELDS=("link_state","wait_a","wait_f","wait_b","wait_c","wait_d","wait_e","wait_h","wait_l","wait_called","sound_called","delay_frames")
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV; f:claripy.ast.BV; b:claripy.ast.BV; c:claripy.ast.BV; d:claripy.ast.BV; e:claripy.ast.BV; h:claripy.ast.BV; l:claripy.ast.BV
 link_state:claripy.ast.BV; wait_a:claripy.ast.BV; wait_f:claripy.ast.BV; wait_b:claripy.ast.BV; wait_c:claripy.ast.BV; wait_d:claripy.ast.BV; wait_e:claripy.ast.BV; wait_h:claripy.ast.BV; wait_l:claripy.ast.BV; wait_called:claripy.ast.BV; sound_called:claripy.ast.BV; delay_frames:claripy.ast.BV
 constraints:tuple[claripy.ast.Bool,...]
class LoadLink(angr.SimProcedure):
 def run(self)->None:self.state.regs.a=self.state.globals['link_state'];self.jump(self.state.addr+3)
class BranchZ(angr.SimProcedure):
 def __init__(self,taken,fallthrough):super().__init__();self.taken=taken;self.fallthrough=fallthrough
 def run(self)->None:
  self.inhibit_autoret=True;c=(self.state.regs.f&0x40)!=0;self.successors.add_successor(self.state.copy(),self.taken,c,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.fallthrough,claripy.Not(c),'Ijk_Boring')
class WaitSummary(angr.SimProcedure):
 def run(self)->None:
  for r,f in (('a','wait_a'),('b','wait_b'),('c','wait_c'),('d','wait_d'),('e','wait_e'),('h','wait_h'),('l','wait_l')):setattr(self.state.regs,r,self.state.globals[f])
  self.state.regs.f=sm83_flags_to_z80(self.state.globals['wait_f']);self.jump(self.state.addr+3)
class LoadSfx(angr.SimProcedure):
 def run(self)->None:self.state.regs.a=0x90;self.jump(self.state.addr+2)
class NormalBoundary(angr.SimProcedure):
 def run(self)->None:self.state.globals['wait_called']=claripy.BVV(1,8);self.state.globals['sound_called']=claripy.BVV(1,8);self.state.globals['delay_frames']=claripy.BVV(0,8);self.jump(DONE)
class LinkBoundary(angr.SimProcedure):
 def run(self)->None:self.state.globals['wait_called']=claripy.BVV(0,8);self.state.globals['sound_called']=claripy.BVV(0,8);self.state.globals['delay_frames']=claripy.BVV(65,8);self.jump(DONE)
class LoadC65(angr.SimProcedure):
 def run(self)->None:self.state.regs.c=65;self.jump(self.state.addr+2)
def _assembly(i):
 l=symbol_location(SYMBOLS,'ManualTextScroll');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q})
 p.hook(q,LoadLink(),length=3);p.hook(q+3,Sm83CpImmediate(4,q+5),length=2);p.hook(q+5,BranchZ(q+15,q+7),length=2);p.hook(q+7,WaitSummary(),length=3);p.hook(q+10,LoadSfx(),length=2);p.hook(q+12,NormalBoundary(),length=3);p.hook(q+15,LoadC65(),length=2);p.hook(q+17,LinkBoundary(),length=3)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for f in FIELDS:s.globals[f]=i[f]
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=2);assert len(m.found)==2
 return [Endpoint(**assembly_registers(x),**{f:x.globals[f] for f in FIELDS},constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_manual_text_scroll');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for off,f in enumerate(FIELDS,8):s.memory.store(NATIVE_STATE+off,i[f])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==2
 return [Endpoint(**native_registers(x,NATIVE_STATE),**{f:x.memory.load(NATIVE_STATE+off,1) for off,f in enumerate(FIELDS,8)},constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_manual_text_scroll_pathwise_equivalence():
 i=symbolic_registers('mts');i['link_state']=claripy.BVS('mts_link_state',8);i['wait_a']=claripy.BVS('mts_wait_a',8);i['wait_f']=claripy.Concat(claripy.BVS('mts_wait_flags',4),claripy.BVV(0,4))
 for f in FIELDS:
  if f not in ('link_state','wait_a','wait_f'):i[f]=claripy.BVS('mts_'+f,8)
 assert_pathwise_equivalent(_assembly(i),_native(i),('a','f','b','c','d','e','h','l',*FIELDS))
def test_manual_text_scroll_exact_body():
 l=symbol_location(SYMBOLS,'ManualTextScroll');assert linked_bytes(ROM,l,20)==bytes.fromhex('fa2bd1fe042808cd65383e90c3b1230e41c33937')
