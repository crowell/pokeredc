from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83DecRegister,Sm83XorImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff
class ReadPalette(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=self.state.globals['background_palette'];self.jump(self.n)  # type: ignore[override]
class StorePalette(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['background_palette']=self.state.regs.a;self.jump(self.n)  # type: ignore[override]
class ReadTile(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=self.state.globals['tile_ids'][self.state.globals['index']];self.jump(self.n)  # type: ignore[override]
class StoreTile(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  i=self.state.globals['index'];self.state.globals['tile_ids'][i]=self.state.regs.a;self.state.globals['index']=i+1;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p);i['background_palette']=claripy.BVS(p+'_bgp',8);i['tile_ids']=claripy.BVS(p+'_tiles',160);return i
def assembly(i):
 l=symbol_location(SYMBOLS,'Trade_AnimCircledMon');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q+3,ReadPalette(q+5),length=2);p.hook(q+5,Sm83XorImmediate(0x3c,q+7),length=2);p.hook(q+7,StorePalette(q+9),length=2);p.hook(q+17,ReadTile(q+18),length=1);p.hook(q+18,Sm83XorImmediate(0x40,q+20),length=2);p.hook(q+20,StoreTile(q+21),length=1);p.hook(q+21,Sm83AddHlRegisterPair('de',q+22),length=1);p.hook(q+22,Sm83DecRegister('c',q+23),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.globals['background_palette']=i['background_palette'];s.globals['tile_ids']=[i['tile_ids'][159-j*8:152-j*8] for j in range(20)];s.globals['index']=0;s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');return [E(**assembly_registers(x),memory=claripy.Concat(x.globals['background_palette'],*x.globals['tile_ids']),constraints=tuple(x.solver.constraints)) for x in collect_returns(p,s,RETURN)]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_trade_anim_circled_mon');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(i['background_palette'],i['tile_ids']));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,21),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('trade_circled');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'Trade_AnimCircledMon');assert linked_bytes(ROM,l,29)==bytes.fromhex('d5c5e5f047ee3ce0472102c31104000e147eee4077190d20f8e1c1d1c9')
