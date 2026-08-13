from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AndImmediate,Sm83DecRegister,Sm83IncRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff;KEYS=('sprite_flipped','predef_h','predef_l','start_tile_id')
class Read(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)  # type: ignore[override]
class StoreWrite(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  i=self.state.globals['write_index'];self.state.globals['writes'][i]=self.state.regs.a;self.state.globals['write_index']=i+1;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 i['writes']=claripy.BVS(p+'_writes',49*8);return i
def assembly(symbol,i):
 l=symbol_location(SYMBOLS,symbol);body=symbol_location(SYMBOLS,'CopyUncompressedPicToHL').address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address})
 if symbol=='CopyUncompressedPicToTilemap':
  q=l.address;p.hook(q,Read('predef_h',q+3),length=3);p.hook(q+4,Read('predef_l',q+7),length=3);p.hook(q+8,Read('start_tile_id',q+10),length=2)
 q=body;p.hook(q+7,Read('sprite_flipped',q+10),length=3);p.hook(q+10,Sm83AndImmediate(0xff,q+11),length=1);p.hook(q+16,StoreWrite(q+17),length=1);p.hook(q+17,Sm83AddHlRegisterPair('de',q+18),length=1);p.hook(q+18,Sm83IncRegister('a',q+19),length=1);p.hook(q+19,Sm83DecRegister('c',q+20),length=1);p.hook(q+25,Sm83DecRegister('b',q+26),length=1);p.hook(q+32,Sm83DecRegister('c',q+33),length=1);p.hook(q+33,Sm83AddHlRegisterPair('bc',q+34),length=1);p.hook(q+38,StoreWrite(q+39),length=1);p.hook(q+39,Sm83AddHlRegisterPair('de',q+40),length=1);p.hook(q+40,Sm83IncRegister('a',q+41),length=1);p.hook(q+41,Sm83DecRegister('c',q+42),length=1);p.hook(q+47,Sm83DecRegister('b',q+48),length=1)
 s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
 s.globals['writes']=[i['writes'][(48-j)*8+7:(48-j)*8] for j in range(49)];s.globals['write_index']=0;s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');return [E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[k] for k in KEYS),*x.globals['writes']),constraints=tuple(x.solver.constraints)) for x in collect_returns(p,s,RETURN)]
def native(symbol,i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);name='port_'+symbol.replace('CopyUncompressedPicTo','copy_uncompressed_pic_to_').lower();fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS),i['writes']));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,53),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('symbol',('CopyUncompressedPicToHL','CopyUncompressedPicToTilemap'))
def test_equivalence(symbol):
 i=inputs(symbol);assert_pathwise_equivalent(assembly(symbol,i),native(symbol,i),(*REGISTERS,'memory'))
def test_exact_bodies():
 a=symbol_location(SYMBOLS,'CopyUncompressedPicToTilemap');assert linked_bytes(ROM,a,10)==bytes.fromhex('fa4fcc67fa50cc6ff0e1');b=symbol_location(SYMBOLS,'CopyUncompressedPicToHL');assert linked_bytes(ROM,b,51)==bytes.fromhex('010707111400f5faaad0a72010f1c5e577193c0d20fae123c10520f2c9c506000d09c1f1c5e577193c0d20fae12bc10520f2c9')
