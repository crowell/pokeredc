from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddImmediate,Sm83AndImmediate,Sm83AndRegister,Sm83BitRegister,Sm83ResRegister,Sm83StoreAAtHlIncrement
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;STACK=0xd000;RETURN=0xffff
DEST=0xc4e1;WINDOW=4;DELAY_ENTRY=0x38d3
EXPECTED=bytes.fromhex('e60fa72815cb78280bcb68280536f023cba8cbb8c6f622c3d338cb7828f6cb70c023c9')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;hl:claripy.ast.BV
 window:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 v=symbolic_registers(p);v['window_in']=claripy.BVS(f'{p}_window_in',8*WINDOW)
 return v
def setup(s,v,native:bool):
 o=NM if native else 0
 s.memory.store(o+DEST,v['window_in'])
class Jmp(angr.SimProcedure):
 """Unconditional jump kept as an explicit hook (the delay-tail
 continuation terminal)."""
 def __init__(self,t:int)->None:
  super().__init__();self._t=t
 def run(self):
  self.jump(self._t)
class StoreHLConst(angr.SimProcedure):
 """SM83 `LD [HL],n`."""
 def __init__(self,val:int,n:int)->None:
  super().__init__();self._v=val;self._n=n
 def run(self):
  self.state.memory.store(self.state.regs.hl,claripy.BVV(self._v,8));self.jump(self._n)
class IncHL(angr.SimProcedure):
 """SM83 `INC HL`."""
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  self.state.regs.hl=self.state.regs.hl+1;self.jump(self._n)
class Fork(angr.SimProcedure):
 """Fork a conditional branch whose taken side may return to the caller
 frame (the bundled Z80 SLEIGH does not fork conditional JR/JP/RET)."""
 def __init__(self,taken:int,fall:int,bit:int,invert:bool,taken_sp:int|None=None)->None:
  super().__init__();self._taken=taken;self._fall=fall;self._bit=bit;self._invert=invert;self._sp=taken_sp
 def run(self):
  f=self.state.regs.f;flag=(f>>self._bit)&1
  cond=(flag==0) if self._invert else (flag==1)
  ts=self.state.copy();fs=self.state.copy()
  ts.solver.add(cond);fs.solver.add(claripy.Not(cond))
  ts.regs.ip=claripy.BVV(self._taken,16);fs.regs.ip=claripy.BVV(self._fall,16)
  if self._sp is not None:ts.regs.sp=claripy.BVV(self._sp,16)
  self.inhibit_autoret=True
  self.successors.add_successor(ts,self._taken,cond,'Ijk_Boring')
  self.successors.add_successor(fs,self._fall,claripy.Not(cond),'Ijk_Boring')
def assembly(v):
 l=symbol_location(SYMS,'PrintBCDDigit');d=symbol_location(SYMS,'PrintLetterDelay')
 assert l.bank==0 and d.bank==0 and d.address==DELAY_ENTRY
 assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+0x00,Sm83AndImmediate(0x0f,b+0x02),length=2)          # and $f
 p.hook(b+0x02,Sm83AndRegister('a',b+0x03),length=1)            # and a
 p.hook(b+0x03,Fork(b+0x1a,b+0x05,6,False),length=2)            # jr z,.zeroDigit
 p.hook(b+0x05,Sm83BitRegister(7,'b',b+0x07),length=2)          # bit 7,b
 p.hook(b+0x07,Fork(b+0x14,b+0x09,6,False),length=2)            # jr z,.outputDigit
 p.hook(b+0x09,Sm83BitRegister(5,'b',b+0x0b),length=2)          # bit 5,b
 p.hook(b+0x0b,Fork(b+0x12,b+0x0d,6,False),length=2)            # jr z,.skipCurrencySymbol
 p.hook(b+0x0d,StoreHLConst(0xf0,b+0x0f),length=2)              # ld [hl],'¥'
 p.hook(b+0x0f,IncHL(b+0x10),length=1)                          # inc hl
 p.hook(b+0x10,Sm83ResRegister(5,'b',b+0x12),length=2)          # res 5,b
 p.hook(b+0x12,Sm83ResRegister(7,'b',b+0x14),length=2)          # res 7,b
 p.hook(b+0x14,Sm83AddImmediate(0xf6,b+0x16),length=2)          # add '0'
 p.hook(b+0x16,Sm83StoreAAtHlIncrement(b+0x17),length=1)        # ld [hli],a
 p.hook(b+0x17,Jmp(DELAY_ENTRY),length=3)                       # jp PrintLetterDelay (continuation)
 p.hook(b+0x1a,Sm83BitRegister(7,'b',b+0x1c),length=2)          # bit 7,b
 p.hook(b+0x1c,Fork(b+0x14,b+0x1e,6,False),length=2)            # jr z,.outputDigit
 p.hook(b+0x1e,Sm83BitRegister(6,'b',b+0x20),length=2)          # bit 6,b
 p.hook(b+0x20,Fork(RETURN,b+0x21,6,True,STACK+2),length=1)     # ret nz
 p.hook(b+0x21,IncHL(b+0x22),length=1)                          # inc hl
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v,False);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(s);m.explore(find=lambda st:st.addr in (RETURN,DELAY_ENTRY),num_find=64);assert not m.errored and len(m.found)==6
 out=[]
 for x in m.found:
  ar=assembly_registers(x)
  out.append(E(**{**{k:v for k,v in ar.items() if k not in ('h','l')},'hl':x.regs.hl},window=claripy.Concat(*(x.memory.load(DEST+i,1) for i in range(WINDOW))),constraints=tuple(x.solver.constraints)))
 return out
def native(v):
 p=angr.Project(ELF,auto_load_libs=False)
 f=p.loader.find_symbol('port_print_bcd_digit_full');assert f
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v,True)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==6
 out=[]
 for x in m.deadended:
  nr=native_registers(x,NS)
  out.append(E(**{**{k:v for k,v in nr.items() if k not in ('h','l')},'hl':claripy.Concat(nr['h'],nr['l'])},window=claripy.Concat(*(x.memory.load(NM+DEST+i,1) for i in range(WINDOW))),constraints=tuple(x.solver.constraints)))
 return out
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_print_bcd_digit_full_pathwise_equivalence():
 v=inputs('bcdd');assert_pathwise_equivalent(assembly(v),native(v),('a','f','b','c','d','e','hl','window'))
