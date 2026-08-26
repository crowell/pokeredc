from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83DecRegister,Sm83LoadAAtHlIncrement,Sm83StoreAAtHlIncrement
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;STACK=0xd000;RETURN=0xffff
REGION=0xc4a4;REGION_LEN=80
EXPECTED=bytes.fromhex('21b8c411a4c4063c2a12130520fa21e1c43e7f0612220520fc0605cdaf200520fac9')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;hl:claripy.ast.BV
 region:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 v=symbolic_registers(p);v['region_in']=claripy.BVS(f'{p}_region_in',8*REGION_LEN)
 return v
def setup(s,v,native:bool):
 o=NM if native else 0
 s.memory.store(o+REGION,v['region_in'])
class LdHLConst(angr.SimProcedure):
 """SM83 `LD HL,nn`."""
 def __init__(self,val:int,n:int)->None:
  super().__init__();self._v=val;self._n=n
 def run(self):
  self.state.regs.hl=claripy.BVV(self._v,16);self.jump(self._n)
class LdDEConst(angr.SimProcedure):
 """SM83 `LD DE,nn`."""
 def __init__(self,val:int,n:int)->None:
  super().__init__();self._v=val;self._n=n
 def run(self):
  self.state.regs.de=claripy.BVV(self._v,16);self.jump(self._n)
class LoadBConst(angr.SimProcedure):
 """SM83 `LD B,n`."""
 def __init__(self,val:int,n:int)->None:
  super().__init__();self._v=val;self._n=n
 def run(self):
  self.state.regs.b=claripy.BVV(self._v,8);self.jump(self._n)
class StoreADE(angr.SimProcedure):
 """SM83 `LD [DE],A`."""
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  self.state.memory.store(self.state.regs.de,self.state.regs.a);self.jump(self._n)
class IncDE(angr.SimProcedure):
 """SM83 `INC DE`."""
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  self.state.regs.de=self.state.regs.de+1;self.jump(self._n)
class Jmp(angr.SimProcedure):
 """Unconditional relative jump kept as an explicit hook so the following
 shimmed instruction starts its own block."""
 def __init__(self,t:int)->None:
  super().__init__();self._t=t
 def run(self):
  self.jump(self._t)
class LoadAConst(angr.SimProcedure):
 """SM83 `LD A,n`."""
 def __init__(self,val:int,n:int)->None:
  super().__init__();self._v=val;self._n=n
 def run(self):
  self.state.regs.a=claripy.BVV(self._v,8);self.jump(self._n)
class DelayFrameSite(angr.SimProcedure):
 """Proved DelayFrame composition boundary at the call site: the
 acknowledged-VBlank terminal leaves A := 0 and F := $50 in the raw
 assembly flag byte."""
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  self.state.regs.a=claripy.BVV(0,8);self.state.regs.f=claripy.BVV(0x50,8);self.jump(self._n)
def assembly(v):
 l=symbol_location(SYMS,'ScrollTextUpOneLine');d=symbol_location(SYMS,'DelayFrame')
 assert l.bank==0 and d.bank==0 and d.address==0x20af
 assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+0,LdHLConst(0xc4b8,b+3),length=3)                    # ld hl,$c4b8
 p.hook(b+3,LdDEConst(0xc4a4,b+6),length=3)                    # ld de,$c4a4
 p.hook(b+6,LoadBConst(60,b+8),length=2)                       # ld b,60
 p.hook(b+8,Sm83LoadAAtHlIncrement(b+9),length=1)              # ld a,[hli]
 p.hook(b+9,StoreADE(b+10),length=1)                           # ld [de],a
 p.hook(b+10,IncDE(b+11),length=1)                             # inc de
 p.hook(b+11,Sm83DecRegister('b',b+12),length=1)               # dec b
 p.hook(b+14,LdHLConst(0xc4e1,b+17),length=3)                  # ld hl,$c4e1
 p.hook(b+17,LoadAConst(0x7f,b+19),length=2)                   # ld a,$7f
 p.hook(b+19,LoadBConst(18,b+21),length=2)                     # ld b,18
 p.hook(b+21,Sm83StoreAAtHlIncrement(b+22),length=1)           # ld [hli],a
 p.hook(b+22,Sm83DecRegister('b',b+23),length=1)               # dec b
 p.hook(b+25,LoadBConst(5,b+27),length=2)                      # ld b,5
 p.hook(b+27,DelayFrameSite(b+30),length=3)                    # call DelayFrame
 p.hook(b+30,Sm83DecRegister('b',b+31),length=1)               # dec b
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v,False);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(s);m.explore(find=lambda st:st.addr==RETURN,num_find=64);assert not m.errored and len(m.found)==1
 out=[]
 for x in m.found:
  ar=assembly_registers(x)
  out.append(E(**{**{k:v for k,v in ar.items() if k not in ('h','l')},'hl':x.regs.hl},region=claripy.Concat(*(x.memory.load(REGION+i,1) for i in range(REGION_LEN))),constraints=tuple(x.solver.constraints)))
 return out
def native(v):
 p=angr.Project(ELF,auto_load_libs=False)
 f=p.loader.find_symbol('port_scroll_text_up_one_line');assert f
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v,True)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1
 out=[]
 for x in m.deadended:
  nr=native_registers(x,NS)
  out.append(E(**{**{k:v for k,v in nr.items() if k not in ('h','l')},'hl':claripy.Concat(nr['h'],nr['l'])},region=claripy.Concat(*(x.memory.load(NM+REGION+i,1) for i in range(REGION_LEN))),constraints=tuple(x.solver.constraints)))
 return out
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_scroll_text_up_one_line_pathwise_equivalence():
 v=inputs('stupl');assert_pathwise_equivalent(assembly(v),native(v),('a','f','b','c','d','e','hl','region'))
