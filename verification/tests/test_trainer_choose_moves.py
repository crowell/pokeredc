from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AddRegister,Sm83AndImmediate,Sm83CpImmediate,Sm83DecRegister,Sm83IncRegister,Sm83SwapRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000
NO=0xeff1;YES=0xeff2;ONE=0xeff3;TWO=0xeff4;REPEAT=0xeff5;DONE=0xeff6
NAMES=('disabled_move','trainer_class','modification','fetched_move','fetched_score','written','write_h','write_l','buffer0','buffer1','buffer2','buffer3','enemy0','enemy1','enemy2','enemy3','saved_h','saved_l','dispatched')
class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
class Read(angr.SimProcedure):
 def __init__(self,key,n,inc=False):super().__init__();self.key=key;self.n=n;self.inc=inc
 def run(self):self.state.regs.a=self.state.globals[self.key];self.state.regs.hl=self.state.regs.hl+(1 if self.inc else 0);self.jump(self.n)
class WriteScore(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['written']=self.state.regs.a;self.state.globals['write_h']=self.state.regs.h;self.state.globals['write_l']=self.state.regs.l;self.jump(self.n)
class SaveHL(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['saved_h']=self.state.regs.h;self.state.globals['saved_l']=self.state.regs.l;self.jump(self.n)
class InitBuffer(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  for z in range(4):self.state.globals['buffer'+str(z)]=claripy.BVV(10,8)
  self.state.regs.hl=0xceed;self.jump(self.n)
class DisableStore(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  idx=self.state.regs.c
  for z in range(4):self.state.globals['buffer'+str(z)]=claripy.If(idx==z,claripy.BVV(0x50,8),self.state.globals['buffer'+str(z)])
  self.jump(self.n)
class ClassSelect(angr.SimProcedure):
 def run(self):
  table=bytes.fromhex('00010001000103000100010001020300010200010001000103000100010200010300010300000100010300010200010300010001000100010001000103000102000102000103000100010300010300010001000103000103000103000103000103000103000102000103000103000102030001000100010300');tc=self.state.globals['trainer_class'];expr=claripy.BVV(0x589b,16);aval=tc
  for klass in range(1,48):
   off=0
   for _ in range(klass-1):off=table.index(0,off)+1
   expr=claripy.If(tc==klass,claripy.BVV(0x589b+off,16),expr);aval=claripy.If(tc==klass,claripy.BVV(klass if klass==1 else 0,8),aval)
  carry=claripy.If(tc==1,self.state.regs.f&1,claripy.BVV(0,8));self.state.regs.hl=expr;self.state.regs.a=aval;self.state.regs.b=0;self.state.regs.f=carry|claripy.BVV(0x42,8);self.jump(DONE)
class XorA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=0;self.state.regs.f=claripy.BVV(0x40,8);self.jump(self.n)
class Dispatch(angr.SimProcedure):
 def run(self):self.state.globals['dispatched']=claripy.BVV(1,8);self.jump(YES)
class BranchZ(angr.SimProcedure):
 def __init__(self,z,nz):super().__init__();self.z=z;self.nz=nz
 def run(self):
  self.inhibit_autoret=True;c=(self.state.regs.f&0x40)!=0;self.successors.add_successor(self.state.copy(),self.z,c,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.nz,claripy.Not(c),'Ijk_Boring')
class MinDec(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  old=self.state.globals['fetched_score'];v=old-1;self.state.globals['fetched_score']=v;self.state.globals['written']=v;self.state.globals['write_h']=self.state.regs.h;self.state.globals['write_l']=self.state.regs.l;self.state.regs.f=(self.state.regs.f&1)|2|claripy.If(v==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If((old&15)==0,claripy.BVV(0x10,8),claripy.BVV(0,8));self.jump(self.n)
class UndoInc(MinDec):
 def run(self):
  old=self.state.globals['fetched_score'];v=old+1;self.state.globals['fetched_score']=v;self.state.globals['written']=v;self.state.globals['write_h']=self.state.regs.h;self.state.globals['write_l']=self.state.regs.l;self.state.regs.f=(self.state.regs.f&1)|claripy.If(v==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If((old&15)==15,claripy.BVV(0x10,8),claripy.BVV(0,8));self.jump(self.n)
class FilterStore(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['written']=self.state.regs.a;self.state.globals['write_h']=self.state.regs.h;self.state.globals['write_l']=self.state.regs.l;self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'AIEnemyTrainerChooseMoves');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
def setup(s,i,constraints=()):
 set_assembly_registers(s,i)
 for n in NAMES:s.globals[n]=i[n]
 s.solver.add(*constraints)
def ep(x,c):return E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[n] for n in NAMES)),continuation=claripy.BVV(c,8),constraints=tuple(x.solver.constraints))
def collect(m,targets):
 m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in targets)
  if m.active:m.step()
 return m.found
def assembly_init(i):
 p,q=project();p.hook(q+5,InitBuffer(q+9),length=4);p.hook(q+9,Read('disabled_move',q+12),length=3);p.hook(q+12,Sm83SwapRegister('a',q+14),length=2);p.hook(q+14,Sm83AndImmediate(15,q+16),length=2);p.hook(q+25,Sm83AddHlRegisterPair('bc',q+26),length=1);p.hook(q+26,DisableStore(DONE),length=2);p.hook(q+28,Boundary(DONE),length=3);s=p.factory.blank_state(addr=q);constraint=claripy.LShR(i['disabled_move'],4).ULE(4);setup(s,i,(constraint,));return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_class(i):
 p,q=project();p.hook(q+28,ClassSelect(),length=16);s=p.factory.blank_state(addr=q+28);setup(s,i,(i['trainer_class'].UGE(1),i['trainer_class'].ULE(47)));return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_mod(i):
 p,q=project();p.hook(q+51,Read('modification',q+52,True),length=1);p.hook(q+52,Sm83AndImmediate(0xff,q+53),length=1);p.hook(q+53,BranchZ(NO,q+55),length=2);p.hook(q+55,SaveHL(q+56),length=1);p.hook(q+59,Sm83DecRegister('a',q+60),length=1);p.hook(q+60,Sm83AddRegister('a',q+61),length=1);p.hook(q+64,Sm83AddHlRegisterPair('bc',q+65),length=1);p.hook(q+65,Dispatch(),length=3);s=p.factory.blank_state(addr=q+51);setup(s,i,(i['modification'].ULE(4),));ends=collect(p.factory.simulation_manager(s),{NO,YES});return [ep(x,1 if x.addr==YES else 0) for x in ends]
def assembly_min_begin(i):
 p,q=project();p.hook(q+81,Boundary(DONE),length=1);s=p.factory.blank_state(addr=q+73);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_min(i):
 p,q=project();p.hook(q+81,Read('fetched_move',q+82),length=1);p.hook(q+83,Sm83AndImmediate(0xff,q+84),length=1);p.hook(q+84,BranchZ(NO,q+86),length=2);p.hook(q+86,MinDec(q+87),length=1);p.hook(q+87,BranchZ(TWO,q+89),length=2);p.hook(q+90,Sm83DecRegister('c',q+91),length=1);p.hook(q+91,BranchZ(NO,ONE),length=2);s=p.factory.blank_state(addr=q+81);setup(s,i);ends=collect(p.factory.simulation_manager(s),{NO,ONE,TWO});codes={NO:0,ONE:1,TWO:2};return [ep(x,codes[x.addr]) for x in ends]
def assembly_undo(i):
 p,q=project();p.hook(q+96,UndoInc(q+97),length=1);p.hook(q+98,Sm83IncRegister('a',q+99),length=1);p.hook(q+99,Sm83CpImmediate(5,q+101),length=2);p.hook(q+101,BranchZ(DONE,REPEAT),length=2);s=p.factory.blank_state(addr=q+96);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,DONE});return [ep(x,1 if x.addr==REPEAT else 0) for x in ends]
def assembly_filter_begin(i):
 p,q=project();p.hook(q+111,Boundary(DONE),length=1);s=p.factory.blank_state(addr=q+103);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_filter(i):
 p,q=project();p.hook(q+111,Read('fetched_move',q+112),length=1);p.hook(q+112,Sm83AndImmediate(0xff,q+113),length=1);p.hook(q+116,Read('fetched_score',q+117),length=1);p.hook(q+117,Sm83DecRegister('a',q+118),length=1);p.hook(q+118,BranchZ(q+124,q+120),length=2);p.hook(q+120,XorA(q+121),length=1);p.hook(q+121,FilterStore(q+126),length=1);p.hook(q+124,Read('fetched_move',q+125),length=1);p.hook(q+125,FilterStore(q+126),length=1);p.hook(q+127,Sm83DecRegister('c',q+128),length=1);p.hook(q+128,BranchZ(DONE,REPEAT),length=2);s=p.factory.blank_state(addr=q+111);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,DONE});return [ep(x,1 if x.addr==REPEAT else 0) for x in ends]
def assembly_finish(i):
 p,q=project();p.hook(q+133,Boundary(DONE),length=1);s=p.factory.blank_state(addr=q+130);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def native(name,i,returns,constraints=()):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));s.solver.add(*constraints);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=(x.regs.rax[7:0] if returns else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
CASES=((assembly_init,'port_trainer_choose_moves_init',False),(assembly_class,'port_trainer_choose_moves_class_begin',False),(assembly_mod,'port_trainer_choose_moves_modification',True),(assembly_min_begin,'port_trainer_choose_moves_minimum_begin',False),(assembly_min,'port_trainer_choose_moves_minimum_step',True),(assembly_undo,'port_trainer_choose_moves_undo_step',True),(assembly_filter_begin,'port_trainer_choose_moves_filter_begin',False),(assembly_filter,'port_trainer_choose_moves_filter_step',True),(assembly_finish,'port_trainer_choose_moves_finish',False))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('assembly,name,returns',CASES)
def test_equivalence(assembly,name,returns):
 i=inputs(name);cons=(() if name not in ('port_trainer_choose_moves_init','port_trainer_choose_moves_class_begin','port_trainer_choose_moves_modification') else ((claripy.LShR(i['disabled_move'],4).ULE(4),) if name.endswith('_init') else ((i['trainer_class'].UGE(1),i['trainer_class'].ULE(47)) if name.endswith('_begin') else (i['modification'].ULE(4),))));assert_pathwise_equivalent(assembly(i),native(name,i,returns,cons),(*REGISTERS,'memory','continuation'))
def test_exact_body_and_tables():
 l=symbol_location(SYMBOLS,'AIEnemyTrainerChooseMoves');assert linked_bytes(ROM,l,138)==bytes.fromhex('3e0a21e9ce22222277fa72d0cb37e60f280a21e9ce3d4f0600093650219b58fa31d0470528062aa720fc18f77ea7ca9f57e5e12aa72812e521a3573d874f0600092a666f114b57d5e921e9ce11edcf0e041a13a728f3352806230d28ec18f279342b3cfe0520f921e9ce11edcf0e041aa72001777e3d2804af2218021a22130d20ed21e9cec921edcfc9')
 t=symbol_location(SYMBOLS,'TrainerClassMoveChoiceModifications');assert linked_bytes(ROM,t,121)==bytes.fromhex('00010001000103000100010001020300010200010001000103000100010200010300010300000100010300010200010300010001000100010001000103000102000102000103000100010300010300010001000103000103000103000103000103000103000102000103000103000102030001000100010300')
 p=symbol_location(SYMBOLS,'AIMoveChoiceModificationFunctionPointers');assert linked_bytes(ROM,p,8)==bytes.fromhex('ab57e75717588358')

def test_exact_ai_modification_bodies():
 checks=(
  ('AIMoveChoiceModification1',55,'fa18d0a7c821e8ce11edcf060505c8231aa7c813cd8458facecfa720f0facdcfe5d5c521e257110100cdab3dc1d1e130dc7ec6057718d6'),
  ('StatusAilmentMoveEffects',5,'01204243ff'),
  ('AIMoveChoiceModification2',48,'fad5ccfe01c021e8ce11edcf060505c8231aa7c813cd8458facdcffe0a38effe1a380afe3238e7fe42380218e13518de'),
  ('AIMoveChoiceModification3',108,'21e8ce11edcf060505c8231aa7c813cd8458e5c5d5214964060fcdd635d1c1e1fa1ed1fe1028e138033518dce5d5c5facfcf5721edcf06050e000528252aa72821cd8458facdcffe282816fe292812fe2b280efacfcfba28e1facecfa7200218d94f79c1d1e1a7289f34189c'))
 for name,size,data in checks:assert linked_bytes(ROM,symbol_location(SYMBOLS,name),size)==bytes.fromhex(data)
