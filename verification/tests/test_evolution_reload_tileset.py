from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate
ROOT=Path(__file__).resolve().parents[2];ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';ELF=ROOT/'verification/build/ports.elf';NATIVE=0x100000;DONE=0xeff1
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Read(angr.SimProcedure):
 def run(self):self.state.regs.a=self.state.globals['link'];self.jump(self.state.addr+3)
class Reload(angr.SimProcedure):
 def run(self):self.state.globals['called']=claripy.BVV(1,8);self.jump(DONE)
class Return(angr.SimProcedure):
 def run(self):self.jump(DONE)
class BranchZ(angr.SimProcedure):
 def run(self):
  self.inhibit_autoret=True;c=(self.state.regs.f&0x40)!=0;self.successors.add_successor(self.state.copy(),DONE,c,'Ijk_Boring');self.successors.add_successor(self.state.copy(),symbol_location(SYMBOLS,'ReloadTilesetTilePatterns').address,claripy.Not(c),'Ijk_Boring')
def inp():
 i=symbolic_registers('reload');i['link']=claripy.BVS('reload_link',8);i['called']=claripy.BVS('reload_called',8);return i
def ep(x,native=False):
 r=native_registers(x,NATIVE) if native else assembly_registers(x);m=x.memory.load(NATIVE+8,2) if native else claripy.Concat(x.globals['link'],x.globals['called']);return E(**r,memory=m,constraints=tuple(x.solver.constraints))
def assembly(i):
 l=symbol_location(SYMBOLS,'Evolution_ReloadTilesetTilePatterns');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q,Read(),length=3);p.hook(q+3,Sm83CpImmediate(2,q+5),length=2);p.hook(q+5,BranchZ(),length=4);p.hook(symbol_location(SYMBOLS,'ReloadTilesetTilePatterns').address,Reload(),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.globals['link']=i['link'];s.globals['called']=i['called'];m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr==DONE)
  if m.active:m.step()
 return [ep(x) for x in m.found]
def native(i):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_evolution_reload_tileset_tile_patterns');s=p.factory.call_state(f.rebased_addr,NATIVE);store_native_registers(s,NATIVE,i);s.memory.store(NATIVE+8,claripy.Concat(i['link'],i['called']));m=p.factory.simulation_manager(s);m.run();return [ep(x,True) for x in m.deadended]
def test_equivalence():
 i=inp();assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'Evolution_ReloadTilesetTilePatterns');assert linked_bytes(ROM,l,9)==bytes.fromhex('fa2bd1fe32c8c39030')
