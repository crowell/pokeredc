from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;STACK=0xd000;RETURN=0xffff
TEXTPTR=0xd360;SRC=0xd380;DEST=0xc4e1;STRLEN=5;CONT=0x1b55;HANDLER=0x1b97
HANDLER_EXPECTED=bytes.fromhex('e12a5f2a57e56069cd5519e118b0')
STRING=bytes([0x87,0x84,0x8b,0x8b,0x8e,0x50])  # "HELLO@"

@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;hl:claripy.ast.BV
 window:claripy.ast.BV;string:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]

def inputs(p):
 v=symbolic_registers(p)
 v['a']=claripy.BVV(0,8);v['f']=claripy.BVV(0,8)
 v['b']=claripy.BVV(0xc4,8);v['c']=claripy.BVV(0xe1,8)
 v['h']=claripy.BVV(0xd3,8);v['l']=claripy.BVV(0x60,8)
 v['d']=claripy.BVV(0,8);v['e']=claripy.BVV(0,8)
 for i in range(STRLEN+2):v[f'win{i}']=claripy.BVS(f'{p}_win{i}',8)
 return v

def setup(s,v,native:bool):
 o=NM if native else 0
 s.memory.store(o+TEXTPTR,claripy.BVV(SRC&0xff,8))
 s.memory.store(o+TEXTPTR+1,claripy.BVV(SRC>>8,8))
 for i,c in enumerate(STRING):s.memory.store(o+SRC+i,claripy.BVV(c,8))
 for i in range(STRLEN+2):s.memory.store(o+DEST+i,v[f'win{i}'])

class PopHL(angr.SimProcedure):
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  sp=self.state.solver.eval(self.state.regs.sp)
  lo=self.state.memory.load(sp,1);hi=self.state.memory.load(sp+1,1)
  self.state.regs.hl=claripy.Concat(hi,lo)
  self.state.regs.sp=claripy.BVV(sp+2,16);self.jump(self._n)

class PlaceStringSite(angr.SimProcedure):
 """The proved PlaceString composition boundary under its plain-string
 domain: the characters render as their tile values through the
 destination until the '@' ($50) terminator; the dictionary tokens are
 out of the composed domain (PlaceNextChar's dictionary is separately
 scoped). The exit state: B/C := the destination end, DE := the
 terminator's position, A := $50, F := Z|N from the terminator compare."""
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  d=self.state.solver.eval(self.state.regs.d);e=self.state.solver.eval(self.state.regs.e)
  l=self.state.solver.eval(self.state.regs.l);h=self.state.solver.eval(self.state.regs.h)
  de=(d<<8)|e;hl=(h<<8)|l
  while True:
   ch=self.state.solver.eval(self.state.memory.load(de,1))
   if ch==0x50:break
   self.state.memory.store(hl,claripy.BVV(ch,8));hl+=1
   de+=1
  self.state.regs.b=claripy.BVV((hl>>8)&0xff,8)
  self.state.regs.c=claripy.BVV(hl&0xff,8)
  self.state.regs.d=claripy.BVV((de>>8)&0xff,8)
  self.state.regs.e=claripy.BVV(de&0xff,8)
  self.state.regs.a=claripy.BVV(0x50,8)
  self.state.regs.f=claripy.BVV(0x42,8)
  self.jump(self._n)

class LdAFromHli(angr.SimProcedure):
  """SM83 LD A,(HL+) : A := [HL]; HL++. The generic z80 p-code arch
  mis-decodes the 0x2A opcode as Z80's LD HL,(nn), so we supply the
  correct Game Boy semantics. Reads from the flat memory region where the
  harness stores the test data."""
  def __init__(self,n:int)->None:
   super().__init__();self._n=n
  def run(self):
   hl=claripy.Concat(self.state.regs.h,self.state.regs.l)
   self.state.regs.a=self.state.memory.load(hl,1)
   nh=hl+1
   self.state.regs.h=nh[15:8];self.state.regs.l=nh[7:0]
   self.jump(self._n)
class Jmp(angr.SimProcedure):
  def __init__(self,t:int)->None:
   super().__init__();self._t=t
  def run(self):
   self.jump(self._t)

def assembly(v):
 l=symbol_location(SYMS,'TextCommand_RAM')
 assert l.bank==0 and l.address==HANDLER
 assert linked_bytes(ROM,l,len(HANDLER_EXPECTED))==HANDLER_EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+0x00,PopHL(b+0x01),length=1)                          # pop hl
 p.hook(b+0x01,LdAFromHli(b+0x02),length=1)                     # ld a,[hli]  (z80 mis-decodes 0x2A)
 p.hook(b+0x03,LdAFromHli(b+0x04),length=1)                     # ld a,[hli]  (z80 mis-decodes 0x2A)
 p.hook(b+0x08,PlaceStringSite(b+0x0b),length=3)                 # call PlaceString (proved boundary)
 p.hook(b+0x0c,Jmp(CONT),length=2)                              # jr NextTextCommand
 st=p.factory.blank_state(addr=b);set_assembly_registers(st,v);setup(st,v,False)
 sp=STACK-2
 st.regs.sp=sp;st.memory.store(sp,v['l'],endness='Iend_LE');st.memory.store(sp+1,v['h'],endness='Iend_LE');st.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(st);m.explore(find=lambda st:st.addr==CONT,num_find=64)
 assert not m.errored and len(m.found)==1
 out=[]
 for x in m.found:
  ar=assembly_registers(x)
  out.append(E(**{**{k:v for k,v in ar.items() if k not in ('h','l')},'hl':claripy.Concat(x.regs.h,x.regs.l)},window=claripy.Concat(*(x.memory.load(DEST+i,1) for i in range(STRLEN+2))),string=claripy.Concat(*(x.memory.load(SRC+i,1) for i in range(len(STRING)))),constraints=tuple(x.solver.constraints)))
 return out

def native(v):
 p=angr.Project(ELF,auto_load_libs=False)
 f=p.loader.find_symbol('port_text_command_ram');assert f
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v,True)
 m=p.factory.simulation_manager(s);m.run()
 assert not m.errored and len(m.deadended)==1
 out=[]
 for x in m.deadended:
  nr=native_registers(x,NS)
  out.append(E(**{**{k:v for k,v in nr.items() if k not in ('h','l')},'hl':claripy.Concat(nr['h'],nr['l'])},window=claripy.Concat(*(x.memory.load(NM+DEST+i,1) for i in range(STRLEN+2))),string=claripy.Concat(*(x.memory.load(NM+SRC+i,1) for i in range(len(STRING)))),constraints=tuple(x.solver.constraints)))
 return out

@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_text_command_ram_pathwise_equivalence():
 v=inputs('tram');assert_pathwise_equivalent(assembly(v),native(v),('a','f','b','c','d','e','hl','window','string'))
