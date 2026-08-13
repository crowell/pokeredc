from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AddRegister,Sm83CpImmediate,Sm83CpRegister,Sm83DecRegister,Sm83IncRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000
SCAN=0xeff9;COPY=0xeffa;REPEAT=0xeffb;DONE=0xeffc
NAMES=('joypad_index','which_guy','y_coord','x_coord','entry_y','entry_x','entry_low','entry_high','movement','written','write_h','write_l')
class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
class Read(angr.SimProcedure):
 def __init__(self,key,n,inc=False):super().__init__();self.key=key;self.n=n;self.inc=inc
 def run(self):self.state.regs.a=self.state.globals[self.key];self.state.regs.hl=self.state.regs.hl+(1 if self.inc else 0);self.jump(self.n)
class Write(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.jump(self.n)
class WriteMovement(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['written']=self.state.regs.a;self.state.globals['write_h']=self.state.regs.d;self.state.globals['write_l']=self.state.regs.e;self.jump(self.n)
class LoadHigh(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.h=self.state.globals['entry_high'];self.jump(self.n)
class SelectTable(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  museum=self.state.globals['which_guy']==0;low=claripy.If(museum,claripy.BVV(0xea,8),claripy.BVV(0x06,8));high=claripy.If(museum,claripy.BVV(0x7c,8),claripy.BVV(0x7d,8));self.state.regs.a=low;self.state.regs.h=high;self.state.regs.l=low;self.jump(self.n)
class Branch(angr.SimProcedure):
 def __init__(self,want_z,taken,n):super().__init__();self.want_z=want_z;self.taken=taken;self.n=n
 def run(self):
  self.inhibit_autoret=True;condition=(self.state.regs.f&0x40)!=0
  if not self.want_z:condition=claripy.Not(condition)
  self.successors.add_successor(self.state.copy(),self.taken,condition,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.n,claripy.Not(condition),'Ijk_Boring')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'PewterGuys');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
def setup(s,i,valid=False):
 set_assembly_registers(s,i)
 for n in NAMES:s.globals[n]=i[n]
 if valid:s.solver.add(claripy.Or(i['which_guy']==0,i['which_guy']==1))
def ep(x,c):return E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[n] for n in NAMES)),continuation=claripy.BVV(c,8),constraints=tuple(x.solver.constraints))
def collect(m,targets):
 m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in targets)
  if m.active:m.step()
 return m.found
def assembly_setup(i):
 p,q=project();p.hook(q+3,Read('joypad_index',q+6),length=3);p.hook(q+6,Sm83DecRegister('a',q+7),length=1);p.hook(q+7,Write('joypad_index',q+10),length=3);p.hook(q+13,Sm83AddHlRegisterPair('de',q+14),length=1);p.hook(q+19,Read('which_guy',q+22),length=3);p.hook(q+22,Sm83AddRegister('a',q+23),length=1);p.hook(q+26,Sm83AddHlRegisterPair('bc',q+27),length=1);p.hook(q+27,SelectTable(q+30),length=3);p.hook(q+30,Read('y_coord',q+33),length=3);p.hook(q+34,Read('x_coord',q+37),length=3);p.hook(q+38,Boundary(SCAN),length=1);s=p.factory.blank_state(addr=q);setup(s,i,True);ends=collect(p.factory.simulation_manager(s),{SCAN});return [ep(x,0) for x in ends]
def assembly_scan(i):
 p,q=project();p.hook(q+38,Read('entry_y',q+39,True),length=1);p.hook(q+39,Sm83CpRegister('b',q+40),length=1);p.hook(q+40,Branch(False,q+64,q+42),length=2);p.hook(q+42,Read('entry_x',q+43,True),length=1);p.hook(q+43,Sm83CpRegister('c',q+44),length=1);p.hook(q+44,Branch(False,q+65,q+46),length=2);p.hook(q+46,Read('entry_low',q+47,True),length=1);p.hook(q+47,LoadHigh(q+48),length=1);p.hook(q+49,Boundary(COPY),length=1);s=p.factory.blank_state(addr=q+38);setup(s,i)
 # Replace the loop head only after the first transition by redirecting the back edge.
 p.hook(q+67,Boundary(SCAN),length=2)
 ends=collect(p.factory.simulation_manager(s),{SCAN,COPY});return [ep(x,1 if x.addr==COPY else 0) for x in ends]
def assembly_copy(i):
 p,q=project();p.hook(q+49,Read('movement',q+50,True),length=1);p.hook(q+50,Sm83CpImmediate(0xff,q+52),length=2);p.hook(q+52,Branch(True,DONE,q+53),length=1);p.hook(q+53,WriteMovement(q+54),length=1);p.hook(q+55,Read('joypad_index',q+58),length=3);p.hook(q+58,Sm83IncRegister('a',q+59),length=1);p.hook(q+59,Write('joypad_index',q+62),length=3);p.hook(q+62,Boundary(REPEAT),length=2);s=p.factory.blank_state(addr=q+49);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,DONE});return [ep(x,1 if x.addr==REPEAT else 0) for x in ends]
def native(name,i,returns,valid=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));s.solver.add(claripy.Or(i['which_guy']==0,i['which_guy']==1)) if valid else None;m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=(x.regs.rax[7:0] if returns else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
CASES=((assembly_setup,'port_pewter_guys_setup',False,True),(assembly_scan,'port_pewter_guys_scan_step',True,False),(assembly_copy,'port_pewter_guys_copy_step',True,False))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('assembly,name,returns,valid',CASES)
def test_equivalence(assembly,name,returns,valid):
 i=inputs(name);assert_pathwise_equivalent(assembly(i),native(name,i,returns,valid),(*REGISTERS,'memory','continuation'))
def test_exact_body_and_tables():
 l=symbol_location(SYMBOLS,'PewterGuys');assert linked_bytes(ROM,l,69)==bytes.fromhex('21d3ccfa38cd3dea38cd16005f19545d21e67cfa2fd18706004f092a666ffa61d347fa62d34f2ab820162ab920132a666f2afeffc81213fa38cd3cea38cd18f123232318e1')
 t=symbol_location(SYMBOLS,'PewterMuseumGuyCoords');assert linked_bytes(ROM,t,87)==bytes.fromhex('121bfa7c101bfd7c111a007d111c037d4040ff1020ff4010ff4020ff10221a7d11231f7d1225247d1325307d1124357d20808010ff20801020ff2020200000000000000000ff20204020ff2080200000000000000000ff')
