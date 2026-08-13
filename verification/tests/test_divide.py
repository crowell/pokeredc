from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate,Sm83DecRegister,Sm83IncRegister,Sm83RlRegister,Sm83RrRegister,Sm83SbcRegister,Sm83SlaRegister,Sm83SrlRegister,Sm83SubRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;SUB=0xeffc;SHIFT=0xeffd;FINISH=0xeffe;RETURN=0xefff
NAMES=('dividend0','dividend1','dividend2','dividend3','divisor','buffer0','buffer1','buffer2','buffer3','buffer4')
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
  if self.state.globals.get('entered',False):self.jump(SUB)
  else:self.state.globals['entered']=True;self.state.regs.a=self.state.globals['buffer0'];self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'_Divide');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
def setup(s,i):
 set_assembly_registers(s,i)
 for n in NAMES:s.globals[n]=i[n]
def hook_rw(p,q):
 for off,key,nxt in ((14,'buffer0',16),(17,'dividend1',19),(21,'divisor',23),(24,'dividend0',26),(34,'buffer4',36),(46,'buffer4',48),(52,'buffer3',54),(58,'buffer2',60),(64,'buffer1',66),(76,'buffer0',78),(83,'dividend1',85),(87,'dividend2',89),(91,'dividend3',93),(101,'divisor',103),(107,'buffer0',109),(115,'dividend1',117),(119,'buffer4',121),(123,'buffer3',125),(127,'buffer2',129),(131,'buffer1',133)):p.hook(q+off,Read(key,q+nxt),length=nxt-off)
 for off,key,nxt in ((1,'buffer0',3),(3,'buffer1',5),(5,'buffer2',7),(7,'buffer3',9),(9,'buffer4',11),(29,'dividend0',31),(32,'dividend1',34),(37,'buffer4',39),(50,'buffer4',52),(56,'buffer3',58),(62,'buffer2',64),(68,'buffer1',70),(78,'divisor',80),(81,'buffer0',83),(85,'dividend0',87),(89,'dividend1',91),(93,'dividend2',95),(105,'divisor',107),(111,'buffer0',113),(117,'divisor',119),(121,'dividend3',123),(125,'dividend2',127),(129,'dividend1',131),(133,'dividend0',135)):p.hook(q+off,Write(key,q+nxt),length=nxt-off)
def ep(x,cont):return E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[n] for n in NAMES)),continuation=claripy.BVV(cont,8),constraints=tuple(x.solver.constraints))
def collect(m,targets):
 m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in targets)
  if m.active:m.step()
 return m.found
def assembly_begin(i):
 p,q=project();hook_rw(p,q);p.hook(q,ZeroA(q+1),length=1);p.hook(q+14,Boundary(SUB),length=2,replace=True);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=SUB);return [ep(x,0) for x in m.found]
def assembly_sub(i):
 p,q=project();hook_rw(p,q);p.hook(q+14,LoopRead(q+16),length=2,replace=True);p.hook(q+19,Sm83SubRegister('c',q+20),length=1);p.hook(q+26,Sm83SbcRegister('c',q+27),length=1);p.hook(q+36,Sm83IncRegister('a',q+37),length=1);p.hook(q+41,Boundary(SHIFT),length=1);s=p.factory.blank_state(addr=q+14);setup(s,i);return [ep(x,1 if x.addr==SUB else 0) for x in collect(p.factory.simulation_manager(s),{SUB,SHIFT})]
def assembly_shift(i):
 p,q=project();hook_rw(p,q);p.hook(q+42,Sm83CpImmediate(1,q+44),length=2);p.hook(q+48,Sm83SlaRegister('a',q+50),length=2)
 for off in (54,60,66):p.hook(q+off,Sm83RlRegister('a',q+off+2),length=2)
 p.hook(q+70,Sm83DecRegister('e',q+71),length=1);p.hook(q+80,ZeroA(q+81),length=1);p.hook(q+96,Sm83CpImmediate(1,q+98),length=2);p.hook(q+100,Sm83DecRegister('b',q+101),length=1);p.hook(q+103,Sm83SrlRegister('a',q+105),length=2);p.hook(q+109,Sm83RrRegister('a',q+111),length=2);p.hook(q+14,Boundary(SUB),length=2,replace=True);p.hook(q+115,Boundary(FINISH),length=2,replace=True);s=p.factory.blank_state(addr=q+41);setup(s,i);return [ep(x,1 if x.addr==FINISH else 0) for x in collect(p.factory.simulation_manager(s),{SUB,FINISH})]
def assembly_finish(i):
 p,q=project();hook_rw(p,q);p.hook(q+135,Boundary(RETURN),length=1);s=p.factory.blank_state(addr=q+115);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=RETURN);return [ep(x,0) for x in m.found]
def native(name,i,kind):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;out=[]
 for x in m.deadended:
  cont=x.regs.rax[7:0] if kind in {'sub','shift'} else claripy.BVV(0,8)
  out.append(E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,10),continuation=cont,constraints=tuple(x.solver.constraints)))
 return out
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('asm,name,kind',((assembly_begin,'port_divide_begin','begin'),(assembly_sub,'port_divide_subtract_step','sub'),(assembly_shift,'port_divide_shift_step','shift'),(assembly_finish,'port_divide_finish','finish')))
def test_equivalence(asm,name,kind):
 i=inputs(name);assert_pathwise_equivalent(asm(i),native(name,i,kind),(*REGISTERS,'memory','continuation'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'_Divide');assert linked_bytes(ROM,l,136)==bytes.fromhex('afe09ae09be09ce09de09e3e095ff09a4ff0969157f0994ff09599380ce0957ae096f09e3ce09e18e578fe012845f09ecb27e09ef09dcb17e09df09ccb17e09cf09bcb17e09b1d20163e085ff09ae099afe09af096e095f097e096f098e0977bfe01200105f099cb3fe099f09acb1fe09a189bf096e099f09ee098f09de097f09ce096f09be095c9')
