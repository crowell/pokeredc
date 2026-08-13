from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr, claripy, pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AdcRegister,Sm83AddRegister,Sm83DecRegister,Sm83RlRegister,Sm83SlaRegister,Sm83SrlRegister

ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;LOOP=0xeffd;FINISH=0xeffe;RETURN=0xefff
NAMES=('product0','product1','product2','product3','multiplier','buffer0','buffer1','buffer2','buffer3')

class Read(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)
class Write(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.jump(self.n)
class ZeroA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=claripy.BVV(0,8);self.state.regs.f=claripy.BVV(0x40,8);self.jump(self.n)
class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
class LoopRead(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(LOOP)
  else:self.state.globals['entered']=True;self.state.regs.a=self.state.globals['multiplier'];self.jump(self.n)

@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'_Multiply');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
def setup(s,i):
 set_assembly_registers(s,i)
 for n in NAMES:s.globals[n]=i[n]
def endpoint(x,cont):return E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[n] for n in NAMES)),continuation=claripy.BVV(cont,8),constraints=tuple(x.solver.constraints))
def hook_rw(p,q):
 for off,key,nxt in ((14,'multiplier',16),(22,'buffer3',24),(25,'product3',27),(30,'buffer2',32),(33,'product2',35),(38,'buffer1',40),(41,'product1',43),(46,'buffer0',48),(49,'product0',51),(57,'product3',59),(63,'product2',65),(69,'product1',71),(75,'product0',77),(83,'buffer3',85),(87,'buffer2',89),(91,'buffer1',93),(95,'buffer0',97)):p.hook(q+off,Read(key,q+nxt),length=nxt-off)
 for off,key,nxt in ((4,'product0',6),(6,'buffer0',8),(8,'buffer1',10),(10,'buffer2',12),(12,'buffer3',14),(18,'multiplier',20),(28,'buffer3',30),(36,'buffer2',38),(44,'buffer1',46),(52,'buffer0',54),(61,'product3',63),(67,'product2',69),(73,'product1',75),(79,'product0',81),(85,'product3',87),(89,'product2',91),(93,'product1',95),(97,'product0',99)):p.hook(q+off,Write(key,q+nxt),length=nxt-off)
def assembly_begin(i):
 p,q=project();hook_rw(p,q);p.hook(q+3,ZeroA(q+4),length=1);p.hook(q+14,Boundary(LOOP),length=1,replace=True);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=LOOP);return [endpoint(x,1) for x in m.found]
def assembly_step(i):
 p,q=project();hook_rw(p,q);p.hook(q+14,LoopRead(q+16),length=2,replace=True);p.hook(q+16,Sm83SrlRegister('a',q+18),length=2);p.hook(q+27,Sm83AddRegister('c',q+28),length=1)
 for off in (35,43,51):p.hook(q+off,Sm83AdcRegister('c',q+off+1),length=1)
 p.hook(q+54,Sm83DecRegister('b',q+55),length=1);p.hook(q+59,Sm83SlaRegister('a',q+61),length=2)
 for off in (65,71,77):p.hook(q+off,Sm83RlRegister('a',q+off+2),length=2)
 p.hook(q+83,Boundary(FINISH),length=2,replace=True);s=p.factory.blank_state(addr=q+14);setup(s,i);m=p.factory.simulation_manager(s);m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in {LOOP,FINISH})
  if m.active:m.step()
 return [endpoint(x,1 if x.addr==LOOP else 0) for x in m.found]
def assembly_finish(i):
 p,q=project();hook_rw(p,q);p.hook(q+99,Boundary(RETURN),length=1);s=p.factory.blank_state(addr=q+83);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=RETURN);return [endpoint(x,0) for x in m.found]
def native(name,i,returns):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,9),continuation=(claripy.If(x.regs.rax[7:0]==0,claripy.BVV(1,8),claripy.BVV(0,8)) if returns else claripy.BVV(0 if 'finish' in name else 1,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('asm,name,returns',((assembly_begin,'port_multiply_begin',False),(assembly_step,'port_multiply_step',True),(assembly_finish,'port_multiply_finish',False)))
def test_equivalence(asm,name,returns):
 i=inputs(name);assert_pathwise_equivalent(asm(i),native(name,i,returns),(*REGISTERS,'memory','continuation'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'_Multiply');assert linked_bytes(ROM,l,100)==bytes.fromhex('3e0847afe095e09be09ce09de09ef099cb3fe0993020f09e4ff09881e09ef09d4ff09789e09df09c4ff09689e09cf09b4ff09589e09b05281af098cb27e098f097cb17e097f096cb17e096f095cb17e09518bbf09ee098f09de097f09ce096f09be095c9')
