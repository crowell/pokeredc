from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,sm83_flags_to_z80,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AndImmediate,Sm83BitRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;NATIVE_CALLBACK=0x100100;NATIVE_DEX=0x100200;STACK=0xd000;RETURN=0xffff;KEYS=('fetched_species','pokedex_num','fetched_palette','dispatched')
class Read(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)  # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.jump(self.n)  # type: ignore[override]
class Callback(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  cb=self.state.globals['callback']
  for r in REGISTERS:setattr(self.state.regs,r,sm83_flags_to_z80(cb[r]) if r=='f' else cb[r])
  self.state.globals['pokedex_num']=cb['pokedex_num'];self.state.globals['dispatched']=claripy.BVV(1,8);self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 for r,v in symbolic_registers(p+'_callback').items():i['callback_'+r]=v
 i['callback_pokedex_num']=claripy.BVS(p+'_callback_dex',8);return i
def assembly(i):
 l=symbol_location(SYMBOLS,'DeterminePaletteID');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q,Sm83BitRegister(3,'a',q+2),length=2);p.hook(q+5,Read('fetched_species',q+6),length=1);p.hook(q+6,Store('pokedex_num',q+9),length=3);p.hook(q+9,Sm83AndImmediate(0xff,q+10),length=1);p.hook(q+15,Callback(q+18),length=3);p.hook(q+19,Read('pokedex_num',q+22),length=3);p.hook(q+28,Sm83AddHlRegisterPair('de',q+29),length=1);p.hook(q+29,Read('fetched_palette',q+30),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
 s.globals['dispatched']=claripy.BVV(0,8);s.globals['callback']={r:i['callback_'+r] for r in REGISTERS}|{'pokedex_num':i['callback_pokedex_num']};s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');return [E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[k] for k in KEYS)),constraints=tuple(x.solver.constraints)) for x in collect_returns(p,s,RETURN)]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_determine_palette_id');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE,NATIVE_CALLBACK,NATIVE_DEX);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));store_native_registers(s,NATIVE_CALLBACK,{r:i['callback_'+r] for r in REGISTERS});s.memory.store(NATIVE_DEX,i['callback_pokedex_num']);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('determine_palette');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'DeterminePaletteID');assert linked_bytes(ROM,l,31)==bytes.fromhex('cb5f3e19c07eea1ed1a7280ac53e3acd6d3ec1fa1ed15f160021c865197ec9');assert symbol_location(SYMBOLS,'MonsterPalettes').address==0x65c8
