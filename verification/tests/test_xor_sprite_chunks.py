from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import sys
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddImmediate,Sm83AndRegister,Sm83CpRegister,Sm83IncRegister,Sm83LoadAImmediate,Sm83OrRegister,Sm83StoreAImmediate,Sm83SwapRegister,Sm83XorA
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;DONE=0xefff;STACK=0xd800
B1=0xa188;B2=0xa310;SIZE=392;CURX=0xd0a1;CURY=0xd0a2;WIDTH=0xd0a3;HEIGHT=0xd0a4;FLAGS=0xd0a9;FLIP=0xd0aa;OUT=0xd0ad;CACHED=0xd0af;T0=0xd0b1;T1=0xd0b3;TABLE=0x2867
GLOBALS=(CURX,CURY,WIDTH,HEIGHT,FLAGS,FLIP,OUT,OUT+1,CACHED,CACHED+1,T0,T0+1,T1,T1+1)
EXPECTED=bytes.fromhex('afeaa1d0eaa2d0cd4128faadd06ffaaed067cdd426cd4128faadd06ffaaed067faafd05ffab0d057faaad0a72816d51a47cb37e60fcd3728cb374f78e60fcd3728b1d1122a471aa81213faa2d03ceaa2d047faa4d0b820d0afeaa2d0faa1d0c608eaa1d047faa3d0b820bdafeaa1d0c9')
REV=bytes.fromhex('0008040c020a060e0109050d030b070f')
sys.setrecursionlimit(max(sys.getrecursionlimit(),10000))
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
 memory:claripy.ast.BV;decode_input:claripy.ast.BV;reverse_trace:claripy.ast.BV;reset_calls:claripy.ast.BV;decode_calls:claripy.ast.BV;reverse_calls:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(tag):
 v=symbolic_registers(tag);v['b1']=claripy.BVS(tag+'_b1',SIZE*8);v['b2']=claripy.BVS(tag+'_b2',SIZE*8);v['post_b1']=claripy.BVS(tag+'_post_b1',SIZE*8);v['post_b2']=claripy.BVS(tag+'_post_b2',SIZE*8);v['flags']=claripy.BVS(tag+'_flags',8);v['flip']=claripy.BVS(tag+'_flip',8)
 for i,a in enumerate(GLOBALS):v[f'g{i}']=claripy.BVS(f'{tag}_g{i}',8);v[f'pg{i}']=claripy.BVS(f'{tag}_pg{i}',8)
 for r in REGISTERS:v['post_'+r]=claripy.Concat(claripy.BVS(tag+'_post_flags',4),claripy.BVV(0,4)) if r=='f' else claripy.BVS(tag+'_post_'+r,8)
 return v
def setup(s,v,base,dimension,selected):
 s.memory.store(base+B1,v['b1']);s.memory.store(base+B2,v['b2']);s.memory.store(base+FLAGS,v['flags']);s.memory.store(base+FLIP,v['flip']);s.solver.add((v['flags']&1)==selected)
 for i,a in enumerate(GLOBALS):
  if a not in (FLAGS,FLIP,WIDTH,HEIGHT):s.memory.store(base+a,v[f'g{i}'])
 s.memory.store(base+WIDTH,claripy.BVV(dimension,8));s.memory.store(base+HEIGHT,claripy.BVV(dimension,8));s.memory.store(base+TABLE,claripy.BVV(REV,128))
 for n in ('reset_calls','decode_calls','reverse_calls'):s.globals[n]=claripy.BVV(0,16)
 s.globals['decode_input']=claripy.BVV(0,1);s.globals['reverse_trace']=claripy.BVV(0,1)
 for r in REGISTERS:s.globals['post_'+r]=v['post_'+r]
 s.globals['post_b1']=v['post_b1'];s.globals['post_b2']=v['post_b2']
 for i in range(len(GLOBALS)):s.globals[f'pg{i}']=v[f'pg{i}']
def snap(s,base):return claripy.Concat(*(s.memory.load(base+a,1) for a in GLOBALS),s.memory.load(base+B1,SIZE),s.memory.load(base+B2,SIZE))
def reset_transition(s,base,getregs,setregs):
 r=getregs();flag=s.memory.load(base+FLAGS,1);s.globals['reset_calls']+=1;r['a']=flag;r['f']=(r['f']&0x10)|0x20|claripy.If((flag&1)==0,claripy.BVV(0x80,8),claripy.BVV(0,8));b1=claripy.BVV(B1,16);b2=claripy.BVV(B2,16);de=claripy.If((flag&1)==0,b1,b2);hl=claripy.If((flag&1)==0,b2,b1);r['d']=de[15:8];r['e']=de[7:0];r['h']=hl[15:8];r['l']=hl[7:0];r['a']=r['l'];s.memory.store(base+OUT,r['a']);r['a']=r['h'];s.memory.store(base+OUT+1,r['a']);r['a']=r['e'];s.memory.store(base+CACHED,r['a']);r['a']=r['d'];s.memory.store(base+CACHED+1,r['a']);setregs(r)
def decode_transition(s,base,getregs,setregs):
 r=getregs();s.globals['decode_calls']+=1;s.globals['decode_input']=claripy.Concat(*(r[x] for x in REGISTERS),snap(s,base));s.memory.store(base+B1,s.globals['post_b1']);s.memory.store(base+B2,s.globals['post_b2']);
 for x in REGISTERS:r[x]=s.globals['post_'+x]
 s.memory.store(base+CURX,claripy.BVV(0,8));s.memory.store(base+CURY,claripy.BVV(0,8))
 for i,a in enumerate(GLOBALS):
  if a not in (CURX,CURY,WIDTH,HEIGHT,FLAGS,FLIP):s.memory.store(base+a,s.globals[f'pg{i}'])
 setregs(r)
def reverse_value(a):return ((a&1)<<3)|((claripy.LShR(a,1)&1)<<2)|((claripy.LShR(a,2)&1)<<1)|(claripy.LShR(a,3)&1)
def reverse_transition(s,getregs,setregs,fetched):
 r=getregs();a=r['a'];want=reverse_value(a);s.globals['reverse_calls']+=1;s.globals['reverse_trace']=claripy.Concat(s.globals['reverse_trace'],fetched);pointer=claripy.ZeroExt(8,a)+TABLE;r['d']=pointer[15:8];r['e']=pointer[7:0];r['f']=claripy.If((a&0xf)>=9,claripy.BVV(0x20,8),claripy.BVV(0,8));r['a']=want;setregs(r)
def aregs(s):return assembly_registers(s)
def aset(s,r):set_assembly_registers(s,r)
class ResetA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):reset_transition(self.state,0,lambda:aregs(self.state),lambda r:aset(self.state,r));self.jump(self.n)
class DecodeA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):decode_transition(self.state,0,lambda:aregs(self.state),lambda r:aset(self.state,r));self.jump(self.n)
class ReverseA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):r=aregs(self.state);reverse_transition(self.state,lambda:r,lambda q:aset(self.state,q),reverse_value(r['a']));self.jump(self.n)
class RegCopy(angr.SimProcedure):
 def __init__(self,d,s,n):super().__init__();self.d=d;self.s=s;self.n=n
 def run(self):r=aregs(self.state);r[self.d]=r[self.s];aset(self.state,r);self.jump(self.n)
class LoadHLInc(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):r=aregs(self.state);p=claripy.Concat(r['h'],r['l']);r['a']=self.state.memory.load(p,1);p+=1;r['h']=p[15:8];r['l']=p[7:0];aset(self.state,r);self.jump(self.n)
class LoadDE(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):r=aregs(self.state);r['a']=self.state.memory.load(claripy.Concat(r['d'],r['e']),1);aset(self.state,r);self.jump(self.n)
class StoreDE(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):r=aregs(self.state);self.state.memory.store(claripy.Concat(r['d'],r['e']),r['a']);self.jump(self.n)
class IncDE(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):r=aregs(self.state);p=claripy.Concat(r['d'],r['e'])+1;r['d']=p[15:8];r['e']=p[7:0];aset(self.state,r);self.jump(self.n)
class StackDE(angr.SimProcedure):
 def __init__(self,push,n):super().__init__();self.push=push;self.n=n
 def run(self):
  r=aregs(self.state);sp=self.state.solver.eval(self.state.regs.sp)
  if self.push:self.state.memory.store(sp-1,r['d']);self.state.memory.store(sp-2,r['e']);self.state.regs.sp=sp-2
  else:r['e']=self.state.memory.load(sp,1);r['d']=self.state.memory.load(sp+1,1);aset(self.state,r);self.state.regs.sp=sp+2
  self.jump(self.n)
class XorB(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):r=aregs(self.state);r['a']^=r['b'];r['f']=claripy.If(r['a']==0,claripy.BVV(0x80,8),claripy.BVV(0,8));aset(self.state,r);self.jump(self.n)
class AndImm(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):r=aregs(self.state);r['a']&=0xf;r['f']=claripy.BVV(0x20,8)|claripy.If(r['a']==0,claripy.BVV(0x80,8),claripy.BVV(0,8));aset(self.state,r);self.jump(self.n)
class Fork(angr.SimProcedure):
 def __init__(self,bit,set_,t,f,stable=None):super().__init__();self.bit=bit;self.set=set_;self.t=t;self.f=f;self.stable=stable
 def run(self):
  if self.stable is not None and self.stable in self.state.globals:self.jump(self.t if self.state.globals[self.stable] else self.f);return
  cond=(((self.state.regs.f>>self.bit)&1)==1);cond=cond if self.set else claripy.Not(cond)
  if self.state.solver.is_true(cond):self.jump(self.t);return
  if self.state.solver.is_false(cond):self.jump(self.f);return
  a=self.state.copy();b=self.state.copy();a.solver.add(cond);b.solver.add(claripy.Not(cond));a.regs.ip=self.t;b.regs.ip=self.f
  if self.stable is not None:a.globals[self.stable]=True;b.globals[self.stable]=False
  self.inhibit_autoret=True;self.successors.add_successor(a,self.t,cond,'Ijk_Boring');self.successors.add_successor(b,self.f,claripy.Not(cond),'Ijk_Boring')
class Jump(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
class ResetN(angr.SimProcedure):
 def run(self,p):
  def g():return {x:self.state.memory.load(p+i,1) for i,x in enumerate(REGISTERS)}
  def q(r):self.state.memory.store(p,claripy.Concat(*(r[x] for x in REGISTERS)))
  self.state.memory.store(NM+FLAGS,self.state.memory.load(p+8,1));reset_transition(self.state,NM,g,q)
  for j,a in enumerate((OUT,OUT+1,CACHED,CACHED+1),1):self.state.memory.store(p+8+j,self.state.memory.load(NM+a,1))
class DecodeN(angr.SimProcedure):
 def run(self,p,m):
  def g():return {x:self.state.memory.load(p+i,1) for i,x in enumerate(REGISTERS)}
  def q(r):self.state.memory.store(p,claripy.Concat(*(r[x] for x in REGISTERS)))
  decode_transition(self.state,NM,g,q)
class ReverseN(angr.SimProcedure):
 def run(self,p):
  def g():return {x:self.state.memory.load(p+i,1) for i,x in enumerate(REGISTERS)}
  def q(r):self.state.memory.store(p,claripy.Concat(*(r[x] for x in REGISTERS)))
  reverse_transition(self.state,g,q,self.state.memory.load(p+8,1))
def assembly(v,dimension,selected):
 l=symbol_location(SYMS,'XorSpriteChunks');end=symbol_location(SYMS,'ReverseNybble');table=symbol_location(SYMS,'NybbleReverseTable');assert end.address-l.address==len(EXPECTED) and linked_bytes(ROM,l,len(EXPECTED))==EXPECTED;assert table.address==TABLE and linked_bytes(ROM,table,len(REV))==REV;p=angr.Project(rom_window(ROM,0),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b,Sm83XorA(b+1),length=1)
 for o,a,n in ((1,CURX,4),(4,CURY,7),(78,CURY,81),(89,CURY,92),(97,CURX,100),(108,CURX,111)):p.hook(b+o,Sm83StoreAImmediate(a,b+n),length=n-o)
 for o,a,n in ((10,OUT,13),(14,OUT+1,17),(24,OUT,27),(28,OUT+1,31),(32,CACHED,35),(36,CACHED+1,39),(40,FLIP,43),(74,CURY,77),(82,HEIGHT,85),(92,CURX,95),(101,WIDTH,104)):p.hook(b+o,Sm83LoadAImmediate(a,b+n),length=n-o)
 p.hook(b+7,ResetA(b+10),length=3);p.hook(b+18,DecodeA(b+21),length=3);p.hook(b+21,ResetA(b+24),length=3);p.hook(b+53,ReverseA(b+56),length=3);p.hook(b+62,ReverseA(b+65),length=3)
 for o,d,s,n in ((13,'l','a',14),(17,'h','a',18),(27,'l','a',28),(31,'h','a',32),(35,'e','a',36),(39,'d','a',40),(48,'b','a',49),(58,'c','a',59),(59,'a','b',60),(69,'b','a',70),(81,'b','a',82),(100,'b','a',101)):p.hook(b+o,RegCopy(d,s,b+n),length=n-o)
 p.hook(b+43,Sm83AndRegister('a',b+44),length=1);p.hook(b+44,Fork(6,True,b+68,b+46,'flip'),length=2);p.hook(b+46,StackDE(True,b+47),length=1);p.hook(b+47,LoadDE(b+48),length=1);p.hook(b+49,Sm83SwapRegister('a',b+51),length=2);p.hook(b+51,AndImm(b+53),length=2);p.hook(b+56,Sm83SwapRegister('a',b+58),length=2);p.hook(b+60,AndImm(b+62),length=2);p.hook(b+65,Sm83OrRegister('c',b+66),length=1);p.hook(b+66,StackDE(False,b+67),length=1);p.hook(b+67,StoreDE(b+68),length=1)
 p.hook(b+68,LoadHLInc(b+69),length=1);p.hook(b+70,LoadDE(b+71),length=1);p.hook(b+71,XorB(b+72),length=1);p.hook(b+72,StoreDE(b+73),length=1);p.hook(b+73,IncDE(b+74),length=1);p.hook(b+77,Sm83IncRegister('a',b+78),length=1);p.hook(b+85,Sm83CpRegister('b',b+86),length=1);p.hook(b+86,Fork(6,False,b+40,b+88),length=2);p.hook(b+88,Sm83XorA(b+89),length=1);p.hook(b+95,Sm83AddImmediate(8,b+97),length=2);p.hook(b+104,Sm83CpRegister('b',b+105),length=1);p.hook(b+105,Fork(6,False,b+40,b+107),length=2);p.hook(b+107,Sm83XorA(b+108),length=1);p.hook(b+111,Jump(DONE),length=1)
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);s.regs.sp=STACK;setup(s,v,0,dimension,selected);m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=2);assert not m.errored and len(m.found)==2;return [endpt(x,0) for x in m.found]
def native(v,dimension,selected):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_xor_sprite_chunks');rs=p.loader.find_symbol('port_reset_sprite_buffer_pointers');dd=p.loader.find_symbol('port_sprite_differential_decode');rv=p.loader.find_symbol('port_reverse_nybble');assert f and rs and dd and rv;p.hook(rs.rebased_addr,ResetN());p.hook(dd.rebased_addr,DecodeN());p.hook(rv.rebased_addr,ReverseN());s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v,NM,dimension,selected);m=p.factory.simulation_manager(s);m.run();assert not m.errored and m.deadended;return [endpt(x,NM) for x in m.deadended]
def endpt(s,base):
 r=native_registers(s,NS) if base else assembly_registers(s);return E(**r,memory=snap(s,base),decode_input=s.globals['decode_input'],reverse_trace=s.globals['reverse_trace'],reset_calls=s.globals['reset_calls'],decode_calls=s.globals['decode_calls'],reverse_calls=s.globals['reverse_calls'],constraints=tuple(s.solver.constraints))
def assert_equal(solver,left,right,label):
 difference=left!=right
 if not claripy.is_false(difference) and solver.satisfiable(extra_constraints=(difference,)):raise AssertionError(f'{label} differs')
def assert_chunks(solver,left,right,size,label,chunk=64):
 if left.size()!=size or right.size()!=size:raise AssertionError(f'{label} size differs')
 for offset in range(0,size,chunk):
  hi=size-1-offset;lo=max(0,hi-chunk+1);assert_equal(solver,left[hi:lo],right[hi:lo],f'{label} bits {lo}..{hi}')
def assert_case(a,n,dimension):
 byte_count=dimension*dimension//8
 for endpoint in (*a,*n):
  solver=claripy.Solver();solver.add(endpoint.constraints)
  assert solver.is_true(endpoint.reset_calls==2)
  assert solver.is_true(endpoint.decode_calls==1)
  assert solver.is_true(claripy.Or(endpoint.reverse_calls==0,endpoint.reverse_calls==2*byte_count))
 overlaps=[]
 for ai,left in enumerate(a):
  for ni,right in enumerate(n):
   solver=claripy.Solver();solver.add(left.constraints);solver.add(right.constraints)
   if not solver.satisfiable():continue
   overlaps.append((ai,ni))
   for name in (*REGISTERS,'reset_calls','decode_calls','reverse_calls'):assert_equal(solver,getattr(left,name),getattr(right,name),name)
   if left.reverse_trace.size()!=right.reverse_trace.size():raise AssertionError('reverse_trace size differs')
   assert_chunks(solver,left.reverse_trace,right.reverse_trace,left.reverse_trace.size(),'reverse_trace')
   for name,size in (('memory',len(GLOBALS)+2*SIZE),('decode_input',len(REGISTERS)+len(GLOBALS)+2*SIZE)):
    x=getattr(left,name);y=getattr(right,name)
    assert_chunks(solver,x,y,size*8,name)
 if {left for left,_ in overlaps}!=set(range(len(a))):raise AssertionError('assembly path lacks native overlap')
 if {right for _,right in overlaps}!=set(range(len(n))):raise AssertionError('native path lacks assembly overlap')
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
@pytest.mark.parametrize(('dimension','selected'),((40,0),(40,1),(48,0),(48,1),(56,0),(56,1)),ids=('40-b1','40-b2','48-b1','48-b2','56-b1','56-b2'))
def test_xor_sprite_chunks_pathwise_equivalence(dimension,selected):
 v=inputs(f'xor_sprite_{dimension}_{selected}');assert_case(assembly(v,dimension,selected),native(v,dimension,selected),dimension)
