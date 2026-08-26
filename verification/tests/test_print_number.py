from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddRegister,Sm83AndImmediate,Sm83BitRegister,Sm83CpImmediate,Sm83CpRegister,Sm83DecRegister,Sm83IncRegister,Sm83OrRegister,Sm83SubImmediate,Sm83SubRegister

ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000
REPEAT=0xeff1;DONE=0xeff2
TRACE_SIZE=7
NAMES=(
 'past','number0','number1','number2','power0','power1','power2','saved0','saved1','saved2',
 'source0','source1','source2','written','did_write','write_h','write_l','saved_b','saved_c','saved_d','saved_e',
 'record_writes','write_count',
 *(f'write_trace_value{i}' for i in range(TRACE_SIZE)),
 *(f'write_trace_h{i}' for i in range(TRACE_SIZE)),
 *(f'write_trace_l{i}' for i in range(TRACE_SIZE)),
)

def record_write(state,value,condition=claripy.BoolV(True)):
 count=state.globals['write_count'];active=claripy.And(condition,state.globals['record_writes']!=0,count<TRACE_SIZE)
 for i in range(TRACE_SIZE):
  select=claripy.And(active,count==i)
  state.globals[f'write_trace_value{i}']=claripy.If(select,value,state.globals[f'write_trace_value{i}'])
  state.globals[f'write_trace_h{i}']=claripy.If(select,state.regs.h,state.globals[f'write_trace_h{i}'])
  state.globals[f'write_trace_l{i}']=claripy.If(select,state.regs.l,state.globals[f'write_trace_l{i}'])
 state.globals['write_count']=claripy.If(active,count+1,count)

class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
class Continuation(angr.SimProcedure):
 def __init__(self,c):super().__init__();self.c=c
 def run(self):self.state.globals['continuation']=claripy.BVV(self.c,8);self.jump(DONE)
class WriteTile(angr.SimProcedure):
 def __init__(self,n,immediate=False):super().__init__();self.n=n;self.immediate=immediate
 def run(self):
  value=claripy.BVV(0xf6,8) if self.immediate else self.state.regs.a;record_write(self.state,value);self.state.globals['written']=value;self.state.globals['did_write']=claripy.BVV(1,8);self.state.globals['write_h']=self.state.regs.h;self.state.globals['write_l']=self.state.regs.l;self.jump(self.n)
class WriteTileHli(WriteTile):
 def run(self):
  record_write(self.state,self.state.regs.a);self.state.globals['written']=self.state.regs.a;self.state.globals['did_write']=claripy.BVV(1,8);self.state.globals['write_h']=self.state.regs.h;self.state.globals['write_l']=self.state.regs.l;self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
class LeadingZero(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  d=self.state.regs.d;self.state.regs.f=(self.state.regs.f&1)|0x10|claripy.If((d&0x80)==0,claripy.BVV(0x40,8),claripy.BVV(0,8));w=(d&0x80)!=0
  record_write(self.state,claripy.BVV(0xf6,8),w)
  self.state.globals['written']=claripy.If(w,claripy.BVV(0xf6,8),self.state.globals['written']);self.state.globals['did_write']=claripy.If(w,claripy.BVV(1,8),self.state.globals['did_write']);self.state.globals['write_h']=claripy.If(w,self.state.regs.h,self.state.globals['write_h']);self.state.globals['write_l']=claripy.If(w,self.state.regs.l,self.state.globals['write_l']);self.jump(self.n)
class XorA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=0;self.state.regs.f=claripy.BVV(0x40,8);self.jump(self.n)
class AndA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.f=claripy.BVV(0x10,8)|claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8));self.jump(self.n)
class BranchZ(angr.SimProcedure):
 def __init__(self,z,nz):super().__init__();self.z=z;self.nz=nz
 def run(self):
  self.inhibit_autoret=True;c=(self.state.regs.f&0x40)!=0;self.successors.add_successor(self.state.copy(),self.z,c,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.nz,claripy.Not(c),'Ijk_Boring')
class ReadHram(angr.SimProcedure):
 def __init__(self,offset,n):super().__init__();self.offset=offset;self.n=n
 def run(self):self.state.regs.a=self.state.memory.load(0xff00+self.offset,1);self.jump(self.n)
class WriteHram(angr.SimProcedure):
 def __init__(self,offset,n):super().__init__();self.offset=offset;self.n=n
 def run(self):self.state.memory.store(0xff00+self.offset,self.state.regs.a);self.jump(self.n)
class ReadSource(angr.SimProcedure):
 def __init__(self,index,n):super().__init__();self.index=index;self.n=n
 def run(self):self.state.regs.a=self.state.globals['source'+str(self.index)];self.jump(self.n)
class SaveDE(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['saved_d']=self.state.regs.d;self.state.globals['saved_e']=self.state.regs.e;self.jump(self.n)
class SaveBC(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['saved_b']=self.state.regs.b;self.state.globals['saved_c']=self.state.regs.c;self.jump(self.n)
class IncDE(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.de=self.state.regs.de+1;self.jump(self.n)
class RestoreFinish(angr.SimProcedure):
 def run(self):
  self.state.regs.d=self.state.globals['saved_d'];self.state.regs.e=self.state.globals['saved_e'];self.state.regs.de=self.state.regs.de-1;self.state.regs.b=self.state.globals['saved_b'];self.state.regs.c=self.state.globals['saved_c'];self.jump(DONE)
def hram_hooks(p,q,reads=(),writes=()):
 for off,imm in reads:p.hook(q+off,ReadHram(imm,q+off+2),length=2)
 for off,imm in writes:p.hook(q+off,WriteHram(imm,q+off+2),length=2)

@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'PrintNumber');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
def setup(s,i):
 set_assembly_registers(s,i);s.memory.store(0xff95,claripy.Concat(*(i[n] for n in NAMES[:10])))
 for n in NAMES[10:]:s.globals[n]=i[n]
 s.solver.add(i['record_writes']==1,i['write_count']<TRACE_SIZE)
def memory(x):
 return claripy.Concat(x.memory.load(0xff95,10),*(x.globals[n] for n in NAMES[10:]))
def ep(x,c):return E(**assembly_registers(x),memory=memory(x),continuation=(claripy.BVV(c,8) if isinstance(c,int) else c),constraints=tuple(x.solver.constraints))
def collect(m,targets):
 m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in targets)
  if m.active:m.step()
 return m.found
def assembly_begin(i):
 p,q=project();p.hook(q+0xc8,Boundary(DONE),length=1);s=p.factory.blank_state(addr=q+0xc6);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_entry(i):
 p,q=project();hram_hooks(p,q,writes=((2,0x95),(4,0x96),(6,0x97),(0x14,0x96),(0x18,0x97),(0x1c,0x98),(0x21,0x97),(0x25,0x98),(0x2a,0x98)))
 p.hook(q,SaveBC(q+1),length=1);p.hook(q+1,XorA(q+2),length=1);p.hook(q+9,Sm83AndImmediate(15,q+0xb),length=2);p.hook(q+0xb,Sm83CpImmediate(1,q+0xd),length=2);p.hook(q+0xf,Sm83CpImmediate(2,q+0x11),length=2)
 for off,index in ((0x13,0),(0x17,1),(0x1b,2),(0x20,0),(0x24,1),(0x29,0)):p.hook(q+off,ReadSource(index,q+off+1),length=1)
 p.hook(q+0x16,IncDE(q+0x17),length=1);p.hook(q+0x1a,IncDE(q+0x1b),length=1);p.hook(q+0x23,IncDE(q+0x24),length=1);p.hook(q+0x2c,SaveDE(q+0x2d),length=1)
 for off,n in ((0x33,2),(0x37,3),(0x3b,4),(0x3f,5),(0x43,6)):p.hook(q+off,Sm83CpImmediate(n,q+off+2),length=2)
 for c,off in ((2,0x9d),(3,0x8d),(4,0x7c),(5,0x6b),(6,0x59),(7,0x47)):p.hook(q+off,Continuation(c),length=1)
 s=p.factory.blank_state(addr=q);setup(s,i);ends=collect(p.factory.simulation_manager(s),{DONE});return [ep(x,x.globals['continuation']) for x in ends]
def assembly_power(i,start,end,writes,xors=()):
 p,q=project();hram_hooks(p,q,writes=writes)
 for off in xors:p.hook(q+off,XorA(q+off+1),length=1)
 p.hook(q+end,Boundary(DONE),length=3);s=p.factory.blank_state(addr=q+start);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_tens_begin(i):
 p,q=project();hram_hooks(p,q,reads=((0x9f,0x98),));p.hook(q+0xa1,Boundary(DONE),length=1);s=p.factory.blank_state(addr=q+0x9d);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_ones(i):
 p,q=project();p.hook(q+0xc0,Sm83AddRegister('b',q+0xc1),length=1);p.hook(q+0xc1,WriteTileHli(q+0xc2),length=1);p.hook(q+0xc2,RestoreFinish(),length=4);s=p.factory.blank_state(addr=q+0xbe);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_digit(i):
 p,q=project()
 hram_hooks(p,q,reads=((0xc8,0x99),(0xcb,0x96),(0xd5,0x9a),(0xd8,0x97),(0xdf,0x96),(0xe8,0x97),(0xed,0x9b),(0xf0,0x98),(0xf7,0x97),(0xfc,0x96),(0x108,0x98),(0x110,0x9d),(0x114,0x9c),(0x118,0x95)),writes=((0xcd,0x9c),(0xd3,0x96),(0xda,0x9d),(0xe6,0x96),(0xeb,0x97),(0xf2,0x9e),(0x102,0x96),(0x106,0x97),(0x10b,0x98),(0x112,0x97),(0x116,0x96),(0x121,0x95)))
 p.hook(q+0xcf,Sm83CpRegister('b',q+0xd0),length=1);p.hook(q+0xd2,Sm83SubRegister('b',q+0xd3),length=1)
 p.hook(q+0xdc,Sm83CpRegister('b',q+0xdd),length=1);p.hook(q+0xe1,Sm83OrRegister('a',q+0xe3),length=2);p.hook(q+0xe5,Sm83DecRegister('a',q+0xe6),length=1);p.hook(q+0xea,Sm83SubRegister('b',q+0xeb),length=1)
 p.hook(q+0xf4,Sm83CpRegister('b',q+0xf5),length=1);p.hook(q+0xf9,Sm83AndImmediate(0xff,q+0xfa),length=1);p.hook(q+0xfe,Sm83AndImmediate(0xff,q+0xff),length=1);p.hook(q+0x101,Sm83DecRegister('a',q+0x102),length=1);p.hook(q+0x104,XorA(q+0x105),length=1);p.hook(q+0x105,Sm83DecRegister('a',q+0x106),length=1);p.hook(q+0x10a,Sm83SubRegister('b',q+0x10b),length=1);p.hook(q+0x10d,Sm83IncRegister('c',q+0x10e),length=1);p.hook(q+0x10e,Boundary(REPEAT),length=2)
 p.hook(q+0x11a,Sm83OrRegister('c',q+0x11b),length=1);p.hook(q+0x11f,Sm83AddRegister('c',q+0x120),length=1);p.hook(q+0x120,WriteTile(q+0x121),length=1);p.hook(q+0x123,Boundary(DONE),length=1);p.hook(q+0x124,LeadingZero(DONE),length=6)
 s=p.factory.blank_state(addr=q+0xc8);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,DONE});return [ep(x,1 if x.addr==REPEAT else 0) for x in ends]
def assembly_next(i):
 p,q=project();hram_hooks(p,q,reads=((0x132,0x95),));p.hook(q+0x12a,Sm83BitRegister(7,'d',q+0x12c),length=2);p.hook(q+0x12e,Sm83BitRegister(6,'d',q+0x130),length=2);p.hook(q+0x134,AndA(q+0x135),length=1);p.hook(q+0x135,BranchZ(DONE,q+0x136),length=1);p.hook(q+0x137,Boundary(DONE),length=1);s=p.factory.blank_state(addr=q+0x12a);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_tens(i):
 p,q=project();p.hook(q+0xa1,Sm83CpImmediate(10,q+0xa3),length=2);p.hook(q+0xa5,Sm83SubImmediate(10,q+0xa7),length=2);p.hook(q+0xa7,Sm83IncRegister('c',q+0xa8),length=1);p.hook(q+0xa8,Boundary(REPEAT),length=2);p.hook(q+0xaa,Boundary(DONE),length=1);s=p.factory.blank_state(addr=q+0xa1);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,DONE});return [ep(x,1 if x.addr==REPEAT else 0) for x in ends]
def assembly_tens_finish(i):
 p,q=project();hram_hooks(p,q,reads=((0xab,0x95),),writes=((0xae,0x95),));p.hook(q+0xad,Sm83OrRegister('c',q+0xae),length=1);p.hook(q+0xb2,LeadingZero(q+0xb5),length=3,replace=True);p.hook(q+0xb9,Sm83AddRegister('c',q+0xba),length=1);p.hook(q+0xba,WriteTile(q+0xbb),length=1);p.hook(q+0xbb,Boundary(DONE),length=1,replace=True);s=p.factory.blank_state(addr=q+0xaa);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def native(name,i,returns):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));s.solver.add(i['record_writes']==1,i['write_count']<TRACE_SIZE);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=(x.regs.rax[7:0] if returns else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
CASES=((assembly_entry,'port_print_number_begin',True),
 (lambda i:assembly_power(i,0x47,0x53,((0x49,0x99),(0x4d,0x9a),(0x51,0x9b))),'port_print_number_power_millions',False),
 (lambda i:assembly_power(i,0x59,0x65,((0x5b,0x99),(0x5f,0x9a),(0x63,0x9b))),'port_print_number_power_hundred_thousands',False),
 (lambda i:assembly_power(i,0x6b,0x76,((0x6c,0x99),(0x70,0x9a),(0x74,0x9b)),(0x6b,)),'port_print_number_power_ten_thousands',False),
 (lambda i:assembly_power(i,0x7c,0x87,((0x7d,0x99),(0x81,0x9a),(0x85,0x9b)),(0x7c,)),'port_print_number_power_thousands',False),
 (lambda i:assembly_power(i,0x8d,0x97,((0x8e,0x99),(0x91,0x9a),(0x95,0x9b)),(0x8d,0x90)),'port_print_number_power_hundreds',False),
 (assembly_begin,'port_print_number_digit_begin',False),(assembly_digit,'port_print_number_digit_step',True),(assembly_next,'port_print_number_next_digit',False),(assembly_tens_begin,'port_print_number_tens_begin',False),(assembly_tens,'port_print_number_tens_step',True),(assembly_tens_finish,'port_print_number_tens_finish',False),(assembly_ones,'port_print_number_ones_finish',False))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('assembly,name,returns',CASES)
def test_equivalence(assembly,name,returns):
 i=inputs(name);assert_pathwise_equivalent(assembly(i),native(name,i,returns),(*REGISTERS,'memory','continuation'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'PrintNumber');assert linked_bytes(ROM,l,312)==bytes.fromhex('c5afe095e096e09778e60ffe01281afe02280d1ae096131ae097131ae098180c1ae097131ae09818031ae098d5507947af4f78fe022866fe032852fe04283dfe052828fe0628123e0fe0993e42e09a3e40e09bcd253dcd893d3e01e0993e86e09a3ea0e09bcd253dcd893dafe0993e27e09a3e10e09bcd253dcd893dafe0993e03e09a3ee8e09bcd253dcd893dafe099afe09a3e64e09bcd253dcd893d0e00f098fe0a3805d60a0c18f747f095b1e0952005cd833d18043ef68177cd893d3ef68022d11bc1c90e00f09947f096e09cb8384690e096f09a47f097e09db8300bf096f600282f3de096f09790e097f09b47f098e09eb83013f097a72009f096a7280f3de096af3de097f09890e0980c18b8f09de097f09ce096f095b128073ef68177e095c9cb7ac836f6c9cb7a2008cb722804f095a7c823c9')
