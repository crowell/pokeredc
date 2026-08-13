from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddRegister,Sm83DecRegister,Sm83IncRegister,Sm83LoadAImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff;BASE_TILE=0xcd5b
class StoreHli(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  k=self.state.globals.get('index',0);v=list(self.state.globals['output']);v[k]=self.state.regs.a;self.state.globals['output']=v;self.state.globals['index']=k+1;self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
class XorA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=0;self.state.regs.f=0x40;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p);i['base_tile']=claripy.BVS(p+'_base_tile',8)
 for n in range(16):i[f'output{n}']=claripy.BVS(f'{p}_output{n}',8)
 return i
def assembly(i):
 l=symbol_location(SYMBOLS,'WriteAsymmetricMonPartySpriteOAM');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address
 for o in (6,8,12,18):p.hook(q+o,StoreHli(q+o+1),length=1)
 p.hook(q+9,Sm83LoadAImmediate(BASE_TILE,q+12),length=3);p.hook(q+13,Sm83IncRegister('a',q+14),length=1);p.hook(q+14,Sm83StoreAImmediate(BASE_TILE,q+17),length=3);p.hook(q+17,XorA(q+18),length=1);p.hook(q+22,Sm83AddRegister('c',q+23),length=1);p.hook(q+24,Sm83DecRegister('e',q+25),length=1);p.hook(q+31,Sm83AddRegister('b',q+32),length=1);p.hook(q+33,Sm83DecRegister('d',q+34),length=1)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.memory.store(BASE_TILE,i['base_tile']);s.globals['output']=[i[f'output{n}'] for n in range(16)];s.globals['index']=0;s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');ends=collect_returns(p,s,RETURN);assert len(ends)==1;x=ends[0]
 return [E(**assembly_registers(x),memory=claripy.Concat(x.memory.load(BASE_TILE,1),*x.globals['output']),constraints=tuple(x.solver.constraints))]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_write_asymmetric_mon_party_sprite_oam');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(i['base_tile'],*(i[f'output{n}'] for n in range(16))));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,17),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('asymmetric_oam');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'WriteAsymmetricMonPartySpriteOAM');assert linked_bytes(ROM,l,37)==bytes.fromhex('110202d5c578227922fa5bcd223cea5bcdaf22143e08814f1d20eac1d13e0880471520dfc9')
