from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83LoadAAtHlIncrement,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;STACK=0xd000;RETURN=0xffff
WTEXTDEST=0xcc3a;TEXTPTR=0xd360;CONT=0x1b55;HANDLER=0x1bb7
HANDLER_EXPECTED=bytes.fromhex('e12aea3acc4f2aea3bcc47c3551b')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;hl:claripy.ast.BV
 dest_lo:claripy.ast.BV;dest_hi:claripy.ast.BV;op0:claripy.ast.BV;op1:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 v=symbolic_registers(p)
 v['a']=claripy.BVV(0,8);v['f']=claripy.BVV(0,8)
 v['b']=claripy.BVV(0,8);v['c']=claripy.BVV(0,8)
 v['h']=claripy.BVV(0xd3,8);v['l']=claripy.BVV(0x60,8)
 v['d']=claripy.BVV(0,8);v['e']=claripy.BVV(0,8)
 v['dest_lo']=claripy.BVS(f'{p}_dest_lo',8);v['dest_hi']=claripy.BVS(f'{p}_dest_hi',8)
 v['op0']=claripy.BVS(f'{p}_op0',8);v['op1']=claripy.BVS(f'{p}_op1',8)
 return v
def setup(s,v,native:bool):
 o=NM if native else 0
 s.memory.store(o+TEXTPTR,v['op0']);s.memory.store(o+TEXTPTR+1,v['op1'])
 s.memory.store(o+WTEXTDEST,v['dest_lo']);s.memory.store(o+WTEXTDEST+1,v['dest_hi'])
class PopHL(angr.SimProcedure):
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  sp=self.state.solver.eval(self.state.regs.sp)
  lo=self.state.memory.load(sp,1);hi=self.state.memory.load(sp+1,1)
  self.state.regs.hl=claripy.Concat(lo,hi)
  self.state.regs.sp=claripy.BVV(sp+2,16);self.jump(self._n)
class LdCFromA(angr.SimProcedure):
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  self.state.regs.c=self.state.regs.a;self.jump(self._n)
class LdBFromA(angr.SimProcedure):
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  self.state.regs.b=self.state.regs.a;self.jump(self._n)
class Jmp(angr.SimProcedure):
 def __init__(self,t:int)->None:
  super().__init__();self._t=t
 def run(self):
  self.jump(self._t)
def assembly(v):
 l=symbol_location(SYMS,'TextCommand_MOVE')
 assert l.bank==0 and l.address==HANDLER
 assert linked_bytes(ROM,l,len(HANDLER_EXPECTED))==HANDLER_EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+0x00,PopHL(b+0x01),length=1)                          # pop hl
 p.hook(b+0x01,Sm83LoadAAtHlIncrement(b+0x02),length=1)         # ld a,[hli]
 p.hook(b+0x02,Sm83StoreAImmediate(WTEXTDEST,b+0x05),length=3)  # ld [wTextDest],a
 p.hook(b+0x05,LdCFromA(b+0x06),length=1)                       # ld c,a
 p.hook(b+0x06,Sm83LoadAAtHlIncrement(b+0x07),length=1)         # ld a,[hli]
 p.hook(b+0x07,Sm83StoreAImmediate(WTEXTDEST+1,b+0x0a),length=3)  # ld [wTextDest+1],a
 p.hook(b+0x0a,LdBFromA(b+0x0b),length=1)                       # ld b,a
 p.hook(b+0x0b,Jmp(CONT),length=3)                              # jp NextTextCommand (continuation)
 st=p.factory.blank_state(addr=b);set_assembly_registers(st,v);setup(st,v,False)
 sp=STACK-2
 st.regs.sp=sp;st.memory.store(sp,v['h'],endness='Iend_LE');st.memory.store(sp+1,v['l'],endness='Iend_LE');st.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(st);m.explore(find=lambda st:st.addr==CONT,num_find=64);assert not m.errored and len(m.found)==1
 out=[]
 for x in m.found:
  ar=assembly_registers(x)
  out.append(E(**{**{k:v for k,v in ar.items() if k not in ('h','l')},'hl':claripy.Concat(x.regs.h,x.regs.l)},dest_lo=x.memory.load(WTEXTDEST,1),dest_hi=x.memory.load(WTEXTDEST+1,1),op0=x.memory.load(TEXTPTR,1),op1=x.memory.load(TEXTPTR+1,1),constraints=tuple(x.solver.constraints)))
 return out
def native(v):
 p=angr.Project(ELF,auto_load_libs=False)
 f=p.loader.find_symbol('port_text_command_move');assert f
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v,True)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1
 out=[]
 for x in m.deadended:
  nr=native_registers(x,NS)
  out.append(E(**{**{k:v for k,v in nr.items() if k not in ('h','l')},'hl':claripy.Concat(nr['h'],nr['l'])},dest_lo=x.memory.load(NM+WTEXTDEST,1),dest_hi=x.memory.load(NM+WTEXTDEST+1,1),op0=x.memory.load(NM+TEXTPTR,1),op1=x.memory.load(NM+TEXTPTR+1,1),constraints=tuple(x.solver.constraints)))
 return out
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_text_command_move_pathwise_equivalence():
 v=inputs('tmov');assert_pathwise_equivalent(assembly(v),native(v),('a','f','b','c','d','e','hl','dest_lo','dest_hi','op0','op1'))
