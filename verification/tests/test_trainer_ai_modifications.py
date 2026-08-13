from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddImmediate,Sm83AndImmediate,Sm83CpImmediate,Sm83CpRegister,Sm83DecRegister,Sm83IncRegister
ROOT=Path(__file__).resolve().parents[2];ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';ELF=ROOT/'verification/build/ports.elf';NATIVE=0x100000
DONE=0xeff1;READY=0xeff2;PREFER=0xeff3;SCAN=0xeff4;REPEAT=0xeff5
NAMES=('battle_mon_status','layer2_encouragement','move','move_power','move_effect','type_effectiveness','enemy_move_type','score','written','write_h','write_l','read_move_called','effectiveness_called')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Read(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)
class ReadMoveSlot(Read):
 def run(self):self.state.regs.a=self.state.globals['move'];self.jump(self.n)
class ReadMove(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['read_move_called']=claripy.BVV(1,8);self.jump(self.n)
class ReadMoveHli(ReadMoveSlot):
 def run(self):self.state.regs.a=self.state.globals['move'];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
class WriteScore(angr.SimProcedure):
 def __init__(self,n,delta):super().__init__();self.n=n;self.delta=delta
 def run(self):
  old=self.state.globals['score'];value=old+self.delta;self.state.globals['written']=value;self.state.globals['write_h']=self.state.regs.h;self.state.globals['write_l']=self.state.regs.l
  carry=self.state.regs.f&1
  if self.delta<0:self.state.regs.f=carry|2|claripy.If(value==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If((old&15)==0,claripy.BVV(0x10,8),claripy.BVV(0,8))
  else:self.state.regs.a=value;self.state.regs.f=claripy.If(value==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If((old&15)+self.delta>15,claripy.BVV(0x10,8),claripy.BVV(0,8))|claripy.If(old>255-self.delta,claripy.BVV(1,8),claripy.BVV(0,8))
  self.jump(self.n)
class Boundary(angr.SimProcedure):
 def __init__(self,c):super().__init__();self.c=c
 def run(self):self.state.globals['continuation']=claripy.BVV(self.c,8);self.jump(DONE)
class BranchZ(angr.SimProcedure):
 def __init__(self,z,nz):super().__init__();self.z=z;self.nz=nz
 def run(self):
  self.inhibit_autoret=True;c=(self.state.regs.f&0x40)!=0;self.successors.add_successor(self.state.copy(),self.z,c,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.nz,claripy.Not(c),'Ijk_Boring')
class BranchC(angr.SimProcedure):
 def __init__(self,c,nc):super().__init__();self.c=c;self.nc=nc
 def run(self):
  self.inhibit_autoret=True;x=(self.state.regs.f&1)!=0;self.successors.add_successor(self.state.copy(),self.c,x,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.nc,claripy.Not(x),'Ijk_Boring')
class BranchNZ(angr.SimProcedure):
 def __init__(self,nz,z):super().__init__();self.nz=nz;self.z=z
 def run(self):
  self.inhibit_autoret=True;x=(self.state.regs.f&0x40)==0;self.successors.add_successor(self.state.copy(),self.nz,x,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.z,claripy.Not(x),'Ijk_Boring')
class IncPair(angr.SimProcedure):
 def __init__(self,pair,n):super().__init__();self.pair=pair;self.n=n
 def run(self):setattr(self.state.regs,self.pair,getattr(self.state.regs,self.pair)+1);self.jump(self.n)
class Found(angr.SimProcedure):
 def run(self):self.state.regs.c=self.state.regs.a;self.state.globals['continuation']=claripy.BVV(2,8);self.jump(DONE)
class ScanDone(angr.SimProcedure):
 def run(self):self.state.regs.a=self.state.regs.c;self.state.globals['continuation']=claripy.BVV(0,8);self.jump(DONE)
class IncScoreMemory(angr.SimProcedure):
 def run(self):
  old=self.state.globals['score'];value=old+1;self.state.globals['score']=value;self.state.globals['written']=value;self.state.globals['write_h']=self.state.regs.h;self.state.globals['write_l']=self.state.regs.l;self.state.regs.f=(self.state.regs.f&1)|claripy.If(value==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If((old&15)==15,claripy.BVV(0x10,8),claripy.BVV(0,8));self.jump(READY)
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project(name):
 l=symbol_location(SYMBOLS,name);return angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address}),l.address
def setup(s,i):set_assembly_registers(s,i);[s.globals.__setitem__(n,i[n]) for n in NAMES]
def ep(x):return E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[n] for n in NAMES)),continuation=x.globals.get('continuation',claripy.BVV(0,8)),constraints=tuple(x.solver.constraints))
def collect(m):
 m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr==DONE)
  if m.active:m.step()
 return [ep(x) for x in m.found]
def assembly_next(i,name,start):
 p,q=project(name);p.hook(q+start,Sm83DecRegister('b',q+start+1),length=1);p.hook(q+start+1,BranchZ(DONE,q+start+2),length=1);p.hook(q+start+2,IncPair('hl',q+start+3),length=1);p.hook(q+start+3,ReadMoveSlot('move',q+start+4),length=1);p.hook(q+start+4,Sm83AndImmediate(0xff,q+start+5),length=1);p.hook(q+start+5,BranchZ(DONE,q+start+6),length=1);p.hook(q+start+6,IncPair('de',q+start+7),length=1);p.hook(q+start+7,ReadMove(READY),length=3);p.hook(READY,Boundary(1),length=1);s=p.factory.blank_state(addr=q+start);setup(s,i);return collect(p.factory.simulation_manager(s))
def assembly_mod2_begin(i):
 p,q=project('AIMoveChoiceModification2');p.hook(q,Read('layer2_encouragement',q+3),length=3);p.hook(q+3,Sm83CpImmediate(1,q+5),length=2);p.hook(q+5,BranchNZ(DONE,q+6),length=1);p.hook(q+14,Boundary(1),length=1);s=p.factory.blank_state(addr=q);setup(s,i);return collect(p.factory.simulation_manager(s))
def assembly_mod1_begin(i):
 p,q=project('AIMoveChoiceModification1');p.hook(q,Read('battle_mon_status',q+3),length=3);p.hook(q+3,Sm83AndImmediate(0xff,q+4),length=1);p.hook(q+4,BranchZ(DONE,q+5),length=1);p.hook(q+13,Sm83DecRegister('b',q+14),length=1);p.hook(q+14,BranchZ(DONE,q+15),length=1);p.hook(q+15,IncPair('hl',q+16),length=1);p.hook(q+16,ReadMoveSlot('move',q+17),length=1);p.hook(q+17,Sm83AndImmediate(0xff,q+18),length=1);p.hook(q+18,BranchZ(DONE,q+19),length=1);p.hook(q+19,IncPair('de',q+20),length=1);p.hook(q+20,ReadMove(READY),length=3);p.hook(READY,Boundary(1),length=1);s=p.factory.blank_state(addr=q);setup(s,i);return collect(p.factory.simulation_manager(s))
def assembly_mod1_score(i):
 p,q=project('AIMoveChoiceModification1');p.hook(q+23,Read('move_power',q+26),length=3);p.hook(q+26,Sm83AndImmediate(0xff,q+27),length=1);p.hook(q+27,BranchZ(q+29,DONE),length=2);p.hook(q+29,Read('move_effect',q+32),length=3)
 class Array(angr.SimProcedure):
  def run(self):
   a=self.state.regs.a;found=claripy.Or(a==1,a==0x20,a==0x42,a==0x43);self.state.regs.a=claripy.If(found,a,claripy.BVV(0xff,8));self.state.regs.f=claripy.If(found,claripy.BVV(0x41,8),claripy.BVV(0x10,8));self.inhibit_autoret=True;self.successors.add_successor(self.state.copy(),q+48,found,'Ijk_Boring');self.successors.add_successor(self.state.copy(),DONE,claripy.Not(found),'Ijk_Boring')
 p.hook(q+32,Array(),length=16);p.hook(q+48,Read('score',q+49),length=1);p.hook(q+49,Sm83AddImmediate(5,q+51),length=2)
 class Store(angr.SimProcedure):
  def run(self):self.state.globals['written']=self.state.regs.a;self.state.globals['write_h']=self.state.regs.h;self.state.globals['write_l']=self.state.regs.l;self.jump(READY)
 p.hook(q+51,Store(),length=1);p.hook(READY,Boundary(1),length=1);s=p.factory.blank_state(addr=q+23);setup(s,i);return collect(p.factory.simulation_manager(s))
def assembly_mod2_score(i):
 p,q=project('AIMoveChoiceModification2');p.hook(q+24,Read('move_effect',q+27),length=3)
 for off,val in ((27,0x0a),(31,0x1a),(35,0x32),(39,0x42)):p.hook(q+off,Sm83CpImmediate(val,q+off+2),length=2)
 p.hook(q+29,BranchC(DONE,q+31),length=2);p.hook(q+33,BranchC(PREFER,q+35),length=2);p.hook(q+37,BranchC(DONE,q+39),length=2);p.hook(q+41,BranchC(PREFER,DONE),length=2);p.hook(PREFER,WriteScore(READY,-1),length=1);p.hook(READY,Boundary(1),length=1);s=p.factory.blank_state(addr=q+24);setup(s,i);return collect(p.factory.simulation_manager(s))
def assembly_mod3_effect(i):
 p,q=project('AIMoveChoiceModification3');p.hook(q+32,Read('type_effectiveness',q+35),length=3);p.hook(q+35,Sm83CpImmediate(0x10,q+37),length=2);p.hook(q+37,BranchZ(DONE,q+39),length=2);p.hook(q+39,BranchC(SCAN,q+41),length=2);p.hook(q+41,WriteScore(READY,-1),length=1);p.hook(READY,Boundary(1),length=1);p.hook(SCAN,Boundary(2),length=1);s=p.factory.blank_state(addr=q+32);setup(s,i);return collect(p.factory.simulation_manager(s))
def assembly_mod3_scan_begin(i):
 p,q=project('AIMoveChoiceModification3');p.hook(q+47,Read('enemy_move_type',q+50),length=3);p.hook(q+58,Boundary(0),length=1);s=p.factory.blank_state(addr=q+47);setup(s,i);return collect(p.factory.simulation_manager(s))
def assembly_mod3_scan_step(i):
 p,q=project('AIMoveChoiceModification3');p.hook(q+58,Sm83DecRegister('b',q+59),length=1);p.hook(q+59,BranchZ(q+98,q+61),length=2);p.hook(q+61,ReadMoveHli('move',q+62),length=1);p.hook(q+62,Sm83AndImmediate(0xff,q+63),length=1);p.hook(q+63,BranchZ(q+98,q+65),length=2);p.hook(q+65,ReadMove(q+68),length=3);p.hook(q+68,Read('move_effect',q+71),length=3)
 for off,val in ((71,0x28),(75,0x29),(79,0x2b)):p.hook(q+off,Sm83CpImmediate(val,q+off+2),length=2)
 p.hook(q+73,BranchZ(q+97,q+75),length=2);p.hook(q+77,BranchZ(q+97,q+79),length=2);p.hook(q+81,BranchZ(q+97,q+83),length=2);p.hook(q+83,Read('enemy_move_type',q+86),length=3);p.hook(q+86,Sm83CpRegister('d',q+87),length=1);p.hook(q+87,BranchZ(REPEAT,q+89),length=2);p.hook(q+89,Read('move_power',q+92),length=3);p.hook(q+92,Sm83AndImmediate(0xff,q+93),length=1);p.hook(q+93,BranchZ(REPEAT,q+97),length=2);p.hook(q+97,Found(),length=1);p.hook(q+98,ScanDone(),length=1);p.hook(REPEAT,Boundary(1),length=1);s=p.factory.blank_state(addr=q+58);setup(s,i);return collect(p.factory.simulation_manager(s))
def assembly_mod3_scan_finish(i):
 p,q=project('AIMoveChoiceModification3');p.hook(q+102,Sm83AndImmediate(0xff,q+103),length=1);p.hook(q+103,BranchZ(DONE,q+105),length=2);p.hook(q+105,IncScoreMemory(),length=1);p.hook(READY,Boundary(1),length=1);s=p.factory.blank_state(addr=q+102);setup(s,i);return collect(p.factory.simulation_manager(s))
def native(name,i,returns=True):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol(name);s=p.factory.call_state(f.rebased_addr,NATIVE);store_native_registers(s,NATIVE,i);s.memory.store(NATIVE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();return [E(**native_registers(x,NATIVE),memory=x.memory.load(NATIVE+8,len(NAMES)),continuation=(x.regs.rax[7:0] if returns else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
CASES=((lambda i:assembly_next(i,'AIMoveChoiceModification2',14),'port_ai_move_choice_modification_next_move',True),(assembly_mod1_begin,'port_ai_move_choice_modification1_begin',True),(assembly_mod1_score,'port_ai_move_choice_modification1_score',True),(assembly_mod2_begin,'port_ai_move_choice_modification2_begin',True),(assembly_mod2_score,'port_ai_move_choice_modification2_score',True),(assembly_mod3_effect,'port_ai_move_choice_modification3_effectiveness',True),(assembly_mod3_scan_begin,'port_ai_move_choice_modification3_scan_begin',False),(assembly_mod3_scan_step,'port_ai_move_choice_modification3_scan_step',True),(assembly_mod3_scan_finish,'port_ai_move_choice_modification3_scan_finish',True))
@pytest.mark.parametrize('assembly,name,returns',CASES)
def test_equivalence(assembly,name,returns):
 i=inputs(name);assert_pathwise_equivalent(assembly(i),native(name,i,returns),(*REGISTERS,'memory','continuation'))
def test_exact_bodies():
 checks=(('AIMoveChoiceModification1',55,'fa18d0a7c821e8ce11edcf060505c8231aa7c813cd8458facecfa720f0facdcfe5d5c521e257110100cdab3dc1d1e130dc7ec6057718d6'),('StatusAilmentMoveEffects',5,'01204243ff'),('AIMoveChoiceModification2',48,'fad5ccfe01c021e8ce11edcf060505c8231aa7c813cd8458facdcffe0a38effe1a380afe3238e7fe42380218e13518de'),('AIMoveChoiceModification3',108,'21e8ce11edcf060505c8231aa7c813cd8458e5c5d5214964060fcdd635d1c1e1fa1ed1fe1028e138033518dce5d5c5facfcf5721edcf06050e000528252aa72821cd8458facdcffe282816fe292812fe2b280efacfcfba28e1facecfa7200218d94f79c1d1e1a7289f34189c'))
 for n,z,h in checks:assert linked_bytes(ROM,symbol_location(SYMBOLS,n),z)==bytes.fromhex(h)
