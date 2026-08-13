from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83CpImmediate,Sm83IncRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xeffc
NAMES=('pointer_high','pointer_low','direction','probed','written','write_h','write_l')
class Load(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)
class Store(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.jump(self.n)
class Write(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['written']=claripy.BVV(0xff,8);self.state.globals['write_h']=self.state.regs.h;self.state.globals['write_l']=self.state.regs.l;self.jump(self.n)
class Boundary(angr.SimProcedure):
 def run(self):self.jump(DONE)
class ZeroA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=0;self.state.regs.f=0x40;self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def assembly(i):
 loc=symbol_location(SYMBOLS,'BattleTransition_OutwardSpiral_');q=loc.address;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q})
 for off,key,n,l in ((6,'pointer_low',9,3),(10,'pointer_high',13,3),(14,'direction',17,3),(45,'probed',46,1),(55,'probed',56,1),(65,'probed',66,1),(75,'probed',76,1),(86,'direction',89,3)):p.hook(q+off,Load(key,q+n),length=l)
 for off,key,n,l in ((36,'pointer_low',39,3),(40,'pointer_high',43,3),(95,'direction',98,3)):p.hook(q+off,Store(key,q+n),length=l)
 for off,imm,n in ((17,0,19),(21,1,23),(25,2,27),(29,3,31),(46,255,48),(56,255,58),(66,255,68),(76,255,78),(90,4,92)):p.hook(q+off,Sm83CpImmediate(imm,q+n),length=2)
 for off,pair,n in ((51,'bc',52),(54,'de',55),(60,'bc',61),(71,'de',72),(74,'bc',75),(80,'de',81)):p.hook(q+off,Sm83AddHlRegisterPair(pair,q+n),length=1)
 p.hook(q+33,Write(q+35),length=2);p.hook(q+84,Write(q+86),length=2);p.hook(q+89,Sm83IncRegister('a',q+90),length=1);p.hook(q+94,ZeroA(q+95),length=1);p.hook(q+43,Boundary(),length=1)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for n in NAMES:s.globals[n]=i[n]
 m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr==DONE)
  if m.active:m.step()
 return [E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[n] for n in NAMES)),constraints=tuple(x.solver.constraints)) for x in m.found]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_battle_transition_outward_spiral_step');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
def test_equivalence():
 i=inputs('outward');assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'BattleTransition_OutwardSpiral_');assert linked_bytes(ROM,l,100)==bytes.fromhex('01ecff111400fa9bd06ffa9ad067fa9fd0fe002817fe01281dfe022823fe03282936ff7dea9bd07cea9ad0c92b7efeff2022230918eb197efeff2018092b18e1237efeff200e2b1918d7097efeff2004192318cd36fffa9fd03cfe042001afea9fd018bf')
