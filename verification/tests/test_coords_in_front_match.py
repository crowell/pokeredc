from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate,Sm83CpRegister,Sm83DecRegister,Sm83IncRegister,Sm83LoadAImmediate,Sm83StoreAHighImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;STACK=0xd000;RETURN=0xffff;FACING=0xc109;Y=0xd361;X=0xd362;OUTPUT=0xffea
KEYS=('facing','y','x','output')
class XorA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=0;self.state.regs.f=0x40;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in KEYS:i[n]=claripy.BVS(f'{p}_{n}',8)
 return i
def assembly(i):
 l=symbol_location(SYMBOLS,'CheckIfCoordsInFrontOfPlayerMatch');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q,Sm83LoadAImmediate(FACING,q+3),length=3);p.hook(q+3,Sm83CpImmediate(4,q+5),length=2);p.hook(q+7,Sm83CpImmediate(8,q+9),length=2);p.hook(q+11,Sm83CpImmediate(12,q+13),length=2)
 for o,a in ((15,Y),(21,Y),(28,X),(36,X),(42,X),(49,Y)):p.hook(q+o,Sm83LoadAImmediate(a,q+o+3),length=3)
 for o in (18,45):p.hook(q+o,Sm83IncRegister('a',q+o+1),length=1)
 for o in (24,39):p.hook(q+o,Sm83DecRegister('a',q+o+1),length=1)
 for o,r in ((25,'b'),(31,'c'),(46,'c'),(52,'b')):p.hook(q+o,Sm83CpRegister(r,q+o+1),length=1)
 p.hook(q+55,XorA(q+56),length=1);p.hook(q+60,Sm83StoreAHighImmediate(0xea,q+62),length=2);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);s.memory.store(FACING,i['facing']);s.memory.store(Y,i['y']);s.memory.store(X,i['x']);s.memory.store(OUTPUT,i['output']);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');ends=collect_returns(p,s,RETURN)
 return [E(**assembly_registers(e),memory=claripy.Concat(e.memory.load(FACING,1),e.memory.load(Y,1),e.memory.load(X,1),e.memory.load(OUTPUT,1)),constraints=tuple(e.solver.constraints)) for e in ends]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_check_if_coords_in_front_of_player_match');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(e,NATIVE_STATE),memory=e.memory.load(NATIVE_STATE+8,4),constraints=tuple(e.solver.constraints)) for e in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('coords_front');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'CheckIfCoordsInFrontOfPlayerMatch');assert linked_bytes(ROM,l,63)==bytes.fromhex('fa09c1fe04280efe082819fe0c281bfa61d33c1804fa61d33db8201efa62d3b920181813fa62d33d1804fa62d33cb92009fa61d3b82003af18023effe0eac9')
