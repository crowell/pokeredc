from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddImmediate,Sm83AndImmediate,Sm83AndRegister,Sm83BitRegister,Sm83CpImmediate,Sm83DecRegister,Sm83LoadAHighImmediate,Sm83LoadAAtHlIncrement,Sm83LoadAImmediate,Sm83ResRegister,Sm83StoreAHighImmediate,Sm83StoreAAtHlIncrement,Sm83StoreAImmediate,Sm83SwapRegister
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;STACK=0xd000;RETURN=0xffff
BANK_ADDR=0xffb8;R_ROMB=0x2000;H_JOYINPUT=0xfff8;H_JOYLAST=0xffb1;H_JOYRELEASED=0xffb2;H_JOYPRESSED=0xffb3;H_JOYHELD=0xffb4;W_STATUSFLAGS5=0xd730;W_JOYIGNORE=0xcd6b;W_LETTER_PRINTING_DELAY_FLAGS=0xd358;W_OPTIONS=0xd355;H_FRAME_COUNTER=0xffd5
PAD_BUTTONS=0x0f;BIT_DISABLE_JOYPAD=5;JOYPAD_BANK=3
DEST=0xc4e1;WINDOW=4;SRC=0xd35a
NUM=0x15cd;DIGIT=0x1604;DELAY=0x38d3;JW=0x19a;JP=0x4000
NUM_EXPECTED=bytes.fromhex('41cbb9cbb1cba9cb682807cb78200336f0231acb37cd04161acd0416130d20f2cb782812cb7020012bcb68280336f02336f6cdd33823c9')
DIGIT_EXPECTED=bytes.fromhex('e60fa72815cb78280bcb68280536f023cba8cbb8c6f622c3d338cb7828f6cb70c023c9')
DELAY_EXPECTED=bytes.fromhex('fa30d7cb77c0fa58d3cb4fc8e5d5c5fa58d3cb472809fa55d3e60fe0d518043e01e0d5cd9a01f0b4cb4728021804cb4f2805cdaf201805f0d5a720e7c1d1e1c9')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;hl:claripy.ast.BV
 window:claripy.ast.BV;source:claripy.ast.BV
 constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 v=symbolic_registers(p)
 v['c']=claripy.BVV(1,8)
 # The source/destination pointers are concrete in this domain; the BCD
 # source byte and the destination window are the symbolic inputs.
 v['d']=claripy.BVV(0xd3,8);v['e']=claripy.BVV(0x5a,8)
 v['h']=claripy.BVV(0xc4,8);v['l']=claripy.BVV(0xe1,8)
 for name in ('status','lpf','woptions','frame','bank','romb','joy_input','joy_last','joy_released','joy_pressed','joy_held','ignore','source'):v[name]=claripy.BVS(f'{p}_{name}',8)
 for i in range(WINDOW):v[f'win{i}']=claripy.BVS(f'{p}_win{i}',8)
 return v
def setup(s,v,native:bool):
 o=NM if native else 0
 s.memory.store(o+SRC,v['source'])
 for i in range(WINDOW):s.memory.store(o+DEST+i,v[f'win{i}'])
class Push16(angr.SimProcedure):
 def __init__(self,hi:str,lo:str,n:int)->None:
  super().__init__();self._hi=hi;self._lo=lo;self._n=n
 def run(self):
  sp=self.state.solver.eval(self.state.regs.sp)
  self.state.memory.store(sp-1,getattr(self.state.regs,self._hi));self.state.memory.store(sp-2,getattr(self.state.regs,self._lo))
  self.state.regs.sp=claripy.BVV(sp-2,16);self.jump(self._n)
class Pop16(angr.SimProcedure):
 def __init__(self,hi:str,lo:str,n:int)->None:
  super().__init__();self._hi=hi;self._lo=lo;self._n=n
 def run(self):
  sp=self.state.solver.eval(self.state.regs.sp)
  setattr(self.state.regs,self._lo,self.state.memory.load(sp,1));setattr(self.state.regs,self._hi,self.state.memory.load(sp+1,1))
  self.state.regs.sp=claripy.BVV(sp+2,16);self.jump(self._n)
class PushAF(angr.SimProcedure):
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  sp=self.state.solver.eval(self.state.regs.sp)
  self.state.memory.store(sp-1,self.state.regs.a);self.state.memory.store(sp-2,self.state.regs.f)
  self.state.regs.sp=claripy.BVV(sp-2,16);self.jump(self._n)
class PopAF(angr.SimProcedure):
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  sp=self.state.solver.eval(self.state.regs.sp)
  self.state.regs.f=self.state.memory.load(sp,1);self.state.regs.a=self.state.memory.load(sp+1,1)
  self.state.regs.sp=claripy.BVV(sp+2,16);self.jump(self._n)
class LoadAConst(angr.SimProcedure):
 def __init__(self,val:int,n:int)->None:
  super().__init__();self._v=val;self._n=n
 def run(self):
  self.state.regs.a=claripy.BVV(self._v,8);self.jump(self._n)
class LdBFromC(angr.SimProcedure):
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  self.state.regs.b=self.state.regs.c;self.jump(self._n)
class LoadADE(angr.SimProcedure):
 """SM83 `LD A,[DE]`."""
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  self.state.regs.a=self.state.memory.load(self.state.regs.de,1);self.jump(self._n)
class IncDE(angr.SimProcedure):
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  self.state.regs.de=self.state.regs.de+1;self.jump(self._n)
class IncHL(angr.SimProcedure):
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  self.state.regs.hl=self.state.regs.hl+1;self.jump(self._n)
class DecHL(angr.SimProcedure):
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  self.state.regs.hl=self.state.regs.hl-1;self.jump(self._n)
class StoreHLConst(angr.SimProcedure):
 def __init__(self,val:int,n:int)->None:
  super().__init__();self._v=val;self._n=n
 def run(self):
  self.state.memory.store(self.state.regs.hl,claripy.BVV(self._v,8));self.jump(self._n)
class Jmp(angr.SimProcedure):
 def __init__(self,t:int)->None:
  super().__init__();self._t=t
 def run(self):
  self.jump(self._t)
class Fork(angr.SimProcedure):
 """Fork a conditional branch; the taken side may carry an explicit
 post-return stack (the bundled Z80 SLEIGH does not fork
 conditional JR/JP/RET)."""
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
class RetNzStack(angr.SimProcedure):
 """Conditional `RET NZ` whose taken side pops the actual return address
 from the stack."""
 def __init__(self,fall:int,bit:int)->None:
  super().__init__();self._fall=fall;self._bit=bit
 def run(self):
  f=self.state.regs.f;flag=(f>>self._bit)&1
  cond=(flag==0)
  sp=self.state.solver.eval(self.state.regs.sp)
  lo=self.state.memory.load(sp,1);hi=self.state.memory.load(sp+1,1)
  ts=self.state.copy();fs=self.state.copy()
  ts.solver.add(cond);fs.solver.add(claripy.Not(cond))
  ts.regs.sp=claripy.BVV(sp+2,16);ts.regs.ip=claripy.Concat(hi,lo)
  fs.regs.ip=claripy.BVV(self._fall,16)
  self.inhibit_autoret=True
  self.successors.add_successor(ts,ts.regs.ip,cond,'Ijk_Boring')
  self.successors.add_successor(fs,self._fall,claripy.Not(cond),'Ijk_Boring')
class DelayTailIdentity(angr.SimProcedure):
 """The proved PrintLetterDelay tail inside the digit loop: the delay's
 state transition is the identity on this function's observable state
 (A/F are dead on return inside the loop and the register saves are
 balanced); the tail continues at the callee's return address."""
 def run(self):
  sp=self.state.solver.eval(self.state.regs.sp)
  lo=self.state.memory.load(sp,1);hi=self.state.memory.load(sp+1,1)
  self.state.regs.sp=claripy.BVV(sp+2,16)
  self.inhibit_autoret=True
  self.jump(claripy.Concat(hi,lo))
class DoRet(angr.SimProcedure):
 def __init__(self,ret:int,sp:int)->None:
  super().__init__();self._ret=ret;self._sp=sp
 def run(self):
  self.inhibit_autoret=True;self.state.regs.sp=claripy.BVV(self._sp,16);self.jump(self._ret)
class DelayFrameSite(angr.SimProcedure):
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  self.state.regs.a=claripy.BVV(0,8);self.state.regs.f=claripy.BVV(0x50,8);self.jump(self._n)
class SpinBoundary(angr.SimProcedure):
 """The ISR-driven poll spin boundary of the nested PrintLetterDelay:
 the spin terminates in the counter==0 done observation, the three saved
 registers pop, and the RET returns into PrintBCDNumber."""
 def __init__(self,ret:int,sp_final:int)->None:
  super().__init__();self._ret=ret;self._sp=sp_final
 def run(self):
  sp=self.state.solver.eval(self.state.regs.sp)
  self.state.regs.c=self.state.memory.load(sp,1);self.state.regs.b=self.state.memory.load(sp+1,1)
  self.state.regs.e=self.state.memory.load(sp+2,1);self.state.regs.d=self.state.memory.load(sp+3,1)
  self.state.regs.l=self.state.memory.load(sp+4,1);self.state.regs.h=self.state.memory.load(sp+5,1)
  self.state.regs.sp=claripy.BVV(self._sp,16)
  self.state.memory.store(H_FRAME_COUNTER,claripy.BVV(0,8))
  self.state.regs.a=claripy.BVV(0,8);self.state.regs.f=claripy.BVV(0x50,8)
  self.jump(self._ret)
def assembly(v):
 l=symbol_location(SYMS,'PrintBCDNumber')
 assert l.bank==0
 assert linked_bytes(ROM,l,len(NUM_EXPECTED))==NUM_EXPECTED
 assert linked_bytes(ROM,symbol_location(SYMS,'PrintBCDDigit'),len(DIGIT_EXPECTED))==DIGIT_EXPECTED
 assert linked_bytes(ROM,symbol_location(SYMS,'PrintLetterDelay'),len(DELAY_EXPECTED))==DELAY_EXPECTED
 p=angr.Project(rom_window(ROM,JOYPAD_BANK),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 d=DIGIT;y=DELAY;jw=JW;jp=JP
 jret=jw+13;jspr=STACK-12;yret=0x35;ysp=STACK
 # PrintBCDNumber chain
 p.hook(b+0x00,LdBFromC(b+0x01),length=1)                       # ld b,c
 p.hook(b+0x01,Sm83ResRegister(7,'c',b+0x03),length=2)
 p.hook(b+0x03,Sm83ResRegister(6,'c',b+0x05),length=2)
 p.hook(b+0x05,Sm83ResRegister(5,'c',b+0x07),length=2)
 p.hook(b+0x07,Sm83BitRegister(5,'b',b+0x09),length=2)          # bit 5,b
 p.hook(b+0x09,Fork(b+0x12,b+0x0b,6,False),length=2)            # jr z (money clear: skip)
 p.hook(b+0x0b,Sm83BitRegister(7,'b',b+0x0d),length=2)          # bit 7,b
 p.hook(b+0x0d,Fork(b+0x12,b+0x0f,6,True),length=2)             # jr nz (leading-zeroes set: skip)
 p.hook(b+0x0f,StoreHLConst(0xf0,b+0x11),length=2)              # ld [hl],'¥'
 p.hook(b+0x11,IncHL(b+0x12),length=1)                          # inc hl
 p.hook(b+0x12,LoadADE(b+0x13),length=1)                        # ld a,[de]
 p.hook(b+0x13,Sm83SwapRegister('a',b+0x15),length=2)           # swap a
 p.hook(b+0x18,LoadADE(b+0x19),length=1)                        # ld a,[de]
 p.hook(b+0x1c,IncDE(b+0x1d),length=1)                          # inc de
 p.hook(b+0x1d,Sm83DecRegister('c',b+0x1e),length=1)            # dec c
 p.hook(b+0x1e,Fork(b+0x12,b+0x20,6,True),length=2)             # jr nz,.loop
 p.hook(b+0x20,Sm83BitRegister(7,'b',b+0x22),length=2)          # bit 7,b
 p.hook(b+0x22,Fork(b+0x36,b+0x24,6,False),length=2)            # jr z,.done
 p.hook(b+0x24,Sm83BitRegister(6,'b',b+0x26),length=2)          # bit 6,b
 p.hook(b+0x26,Fork(b+0x29,b+0x28,6,True),length=2)             # jr nz,.skipRight
 p.hook(b+0x28,DecHL(b+0x29),length=1)                          # dec hl
 p.hook(b+0x29,Sm83BitRegister(5,'b',b+0x2b),length=2)          # bit 5,b
 p.hook(b+0x2b,Fork(b+0x30,b+0x2d,6,False),length=2)            # jr z,.skipCurrency
 p.hook(b+0x2d,StoreHLConst(0xf0,b+0x2f),length=2)              # ld [hl],'¥'
 p.hook(b+0x2f,IncHL(b+0x30),length=1)                          # inc hl
 p.hook(b+0x30,StoreHLConst(0xf6,b+0x32),length=2)              # ld [hl],'0'
 p.hook(b+0x35,IncHL(b+0x36),length=1)                          # inc hl (post-delay)
 # PrintBCDDigit chain (the proved callee executes for real)
 p.hook(d+0x00,Sm83AndImmediate(0x0f,d+0x02),length=2)
 p.hook(d+0x02,Sm83AndRegister('a',d+0x03),length=1)
 p.hook(d+0x03,Fork(d+0x1a,d+0x05,6,False),length=2)
 p.hook(d+0x05,Sm83BitRegister(7,'b',d+0x07),length=2)
 p.hook(d+0x07,Fork(d+0x14,d+0x09,6,False),length=2)
 p.hook(d+0x09,Sm83BitRegister(5,'b',d+0x0b),length=2)
 p.hook(d+0x0b,Fork(d+0x12,d+0x0d,6,False),length=2)
 p.hook(d+0x0d,StoreHLConst(0xf0,d+0x0f),length=2)
 p.hook(d+0x0f,IncHL(d+0x10),length=1)
 p.hook(d+0x10,Sm83ResRegister(5,'b',d+0x12),length=2)
 p.hook(d+0x12,Sm83ResRegister(7,'b',d+0x14),length=2)
 p.hook(d+0x14,Sm83AddImmediate(0xf6,d+0x16),length=2)
 p.hook(d+0x16,Sm83StoreAAtHlIncrement(d+0x17),length=1)
 p.hook(d+0x17,DelayTailIdentity(),length=3)                    # jp PrintLetterDelay (identity)
 p.hook(d+0x1a,Sm83BitRegister(7,'b',d+0x1c),length=2)
 p.hook(d+0x1c,Fork(d+0x14,d+0x1e,6,False),length=2)
 p.hook(d+0x1e,Sm83BitRegister(6,'b',d+0x20),length=2)
 p.hook(d+0x20,RetNzStack(d+0x21,6),length=1)                   # ret nz
 p.hook(d+0x21,IncHL(d+0x22),length=1)                          # inc hl
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v,False);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(s);m.explore(find=lambda st:st.addr==RETURN,num_find=256);assert not m.errored and len(m.found)>=4
 out=[]
 for x in m.found:
  ar=assembly_registers(x)
  out.append(E(**{**{k:v for k,v in ar.items() if k not in ('h','l')},'hl':x.regs.hl},window=claripy.Concat(*(x.memory.load(DEST+i,1) for i in range(WINDOW))),source=x.memory.load(SRC,1),constraints=tuple(x.solver.constraints)))
 return out
def native(v):
 p=angr.Project(ELF,auto_load_libs=False)
 f=p.loader.find_symbol('port_print_bcd_number');assert f
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v,True)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)>=4
 out=[]
 for x in m.deadended:
  nr=native_registers(x,NS)
  out.append(E(**{**{k:v for k,v in nr.items() if k not in ('h','l')},'hl':claripy.Concat(nr['h'],nr['l'])},window=claripy.Concat(*(x.memory.load(NM+DEST+i,1) for i in range(WINDOW))),source=x.memory.load(NM+SRC,1),constraints=tuple(x.solver.constraints)))
 return out
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_print_bcd_number_pathwise_equivalence():
 v=inputs('bcdnum');assert_pathwise_equivalent(assembly(v),native(v),('a','f','b','c','d','e','hl','window','source'))
