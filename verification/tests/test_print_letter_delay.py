from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83AndRegister,Sm83BitRegister,Sm83CpImmediate,Sm83LoadAHighImmediate,Sm83LoadAImmediate,Sm83StoreAHighImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;STACK=0xd000;RETURN=0xffff
BANK_ADDR=0xffb8;R_ROMB=0x2000;H_JOYINPUT=0xfff8;H_JOYLAST=0xffb1;H_JOYRELEASED=0xffb2;H_JOYPRESSED=0xffb3;H_JOYHELD=0xffb4;W_STATUSFLAGS5=0xd730;W_JOYIGNORE=0xcd6b;W_LETTER_PRINTING_DELAY_FLAGS=0xd358;W_OPTIONS=0xd355;H_FRAME_COUNTER=0xffd5
PAD_BUTTONS=0x0f;BIT_DISABLE_JOYPAD=5;JOYPAD_BANK=3
EXPECTED=bytes.fromhex('fa30d7cb77c0fa58d3cb4fc8e5d5c5fa58d3cb472809fa55d3e60fe0d518043e01e0d5cd9a01f0b4cb4728021804cb4f2805cdaf201805f0d5a720e7c1d1e1c9')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;hl:claripy.ast.BV
 frame:claripy.ast.BV;joy_input:claripy.ast.BV;joy_last:claripy.ast.BV;joy_released:claripy.ast.BV;joy_pressed:claripy.ast.BV;joy_held:claripy.ast.BV
 bank:claripy.ast.BV;romb:claripy.ast.BV;status:claripy.ast.BV;ignore:claripy.ast.BV;lpf:claripy.ast.BV;woptions:claripy.ast.BV
 constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 v=symbolic_registers(p)
 for name in ('status','lpf','woptions','frame','bank','romb','joy_input','joy_last','joy_released','joy_pressed','joy_held','ignore'):v[name]=claripy.BVS(f'{p}_{name}',8)
 return v
def setup(s,v,native:bool):
 o=NM if native else 0
 for name,addr in (('status',W_STATUSFLAGS5),('lpf',W_LETTER_PRINTING_DELAY_FLAGS),('woptions',W_OPTIONS),('frame',H_FRAME_COUNTER),('bank',BANK_ADDR),('romb',R_ROMB),('joy_input',H_JOYINPUT),('joy_last',H_JOYLAST),('joy_released',H_JOYRELEASED),('joy_pressed',H_JOYPRESSED),('joy_held',H_JOYHELD),('ignore',W_JOYIGNORE)):s.memory.store(o+addr,v[name])
class Push16(angr.SimProcedure):
 """SM83 `PUSH r16`: (SP-1):=hi, (SP-2):=lo, SP:=SP-2."""
 def __init__(self,hi:str,lo:str,n:int)->None:
  super().__init__();self._hi=hi;self._lo=lo;self._n=n
 def run(self):
  sp=self.state.solver.eval(self.state.regs.sp)
  self.state.memory.store(sp-1,getattr(self.state.regs,self._hi));self.state.memory.store(sp-2,getattr(self.state.regs,self._lo))
  self.state.regs.sp=claripy.BVV(sp-2,16);self.jump(self._n)
class Pop16(angr.SimProcedure):
 """SM83 `POP r16`: lo:=[SP], hi:=[SP+1], SP:=SP+2."""
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
class Jmp(angr.SimProcedure):
 """Unconditional relative jump kept as an explicit hook so the following
 shimmed instruction starts its own block."""
 def __init__(self,t:int)->None:
  super().__init__();self._t=t
 def run(self):
  self.jump(self._t)
class Fork(angr.SimProcedure):
 """Fork a conditional branch; the taken side may return to a caller frame
 with an explicit stack (the bundled Z80 SLEIGH does not fork
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
class SpinBoundary(angr.SimProcedure):
 """The ISR-driven poll spin boundary: the spin repeats the identical
 poll cycle until the external decrement reaches zero, then the same
 `and a`/done observation runs with hFrameCounter at zero. This terminal
 models that exit: the three saved registers pop, A := 0, F := the AND
 flags in the raw layout, the counter reads zero, and the RET returns to
 the caller."""
 def run(self):
  sp=self.state.solver.eval(self.state.regs.sp)
  self.state.regs.c=self.state.memory.load(sp,1);self.state.regs.b=self.state.memory.load(sp+1,1)
  self.state.regs.e=self.state.memory.load(sp+2,1);self.state.regs.d=self.state.memory.load(sp+3,1)
  self.state.regs.l=self.state.memory.load(sp+4,1);self.state.regs.h=self.state.memory.load(sp+5,1)
  self.state.regs.sp=claripy.BVV(sp+8,16)
  self.state.memory.store(H_FRAME_COUNTER,claripy.BVV(0,8))
  self.state.regs.a=claripy.BVV(0,8);self.state.regs.f=claripy.BVV(0x50,8)
  self.jump(RETURN)
class DoRet(angr.SimProcedure):
 def __init__(self,ret:int,sp:int)->None:
  super().__init__();self._ret=ret;self._sp=sp
 def run(self):
  self.inhibit_autoret=True;self.state.regs.sp=claripy.BVV(self._sp,16);self.jump(self._ret)
class DelayFrameSite(angr.SimProcedure):
 """Proved DelayFrame composition boundary at the call site: the
 acknowledged-VBlank terminal leaves A := 0 and F := $50 in the raw
 assembly flag byte."""
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  self.state.regs.a=claripy.BVV(0,8);self.state.regs.f=claripy.BVV(0x50,8);self.jump(self._n)
class Sm83AndRegisterH(angr.SimProcedure):
 """SM83 `AND r`: A := A & r; Z per result, N=0, H=1, C=0, in the raw
 Z80 flag layout (the harness Sm83AndRegister omits the H bit)."""
 def __init__(self,register:str,n:int)->None:
  super().__init__();self._r=register;self._n=n
 def run(self):
  self.state.regs.a=self.state.regs.a&getattr(self.state.regs,self._r)
  self.state.regs.f=claripy.If(self.state.regs.a==0,claripy.BVV(0x50,8),claripy.BVV(0x10,8))
  self.jump(self._n)
def assembly(v):
 l=symbol_location(SYMS,'PrintLetterDelay');w=symbol_location(SYMS,'Joypad');q=symbol_location(SYMS,'_Joypad')
 assert l.bank==0 and w.bank==0 and q.bank==JOYPAD_BANK
 assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 assert w.address==0x19a and q.address==0x4000
 p=angr.Project(rom_window(ROM,JOYPAD_BANK),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address;q=q.address;jw=0x19a;jret=jw+13;jspr=STACK-10
 p.hook(b+0,Sm83LoadAImmediate(W_STATUSFLAGS5,b+3),length=3)
 p.hook(b+3,Sm83BitRegister(7,'a',b+5),length=2)
 p.hook(b+5,Fork(RETURN,b+6,6,True,STACK+2),length=1)          # ret nz
 p.hook(b+6,Sm83LoadAImmediate(W_LETTER_PRINTING_DELAY_FLAGS,b+9),length=3)
 p.hook(b+9,Sm83BitRegister(1,'a',b+11),length=2)
 p.hook(b+11,Fork(RETURN,b+12,6,False,STACK+2),length=1)       # ret z
 p.hook(b+12,Push16('h','l',b+13),length=1)
 p.hook(b+13,Push16('d','e',b+14),length=1)
 p.hook(b+14,Push16('b','c',b+15),length=1)
 p.hook(b+15,Sm83LoadAImmediate(W_LETTER_PRINTING_DELAY_FLAGS,b+18),length=3)
 p.hook(b+18,Sm83BitRegister(0,'a',b+20),length=2)
 p.hook(b+20,Fork(b+31,b+22,6,False),length=2)                 # jr z,.waitOneFrame
 p.hook(b+22,Sm83LoadAImmediate(W_OPTIONS,b+25),length=3)
 p.hook(b+25,Sm83AndImmediate(0x0f,b+27),length=2)
 p.hook(b+27,Sm83StoreAHighImmediate(0xd5,b+29),length=2)      # ldh [hFrameCounter],a
 p.hook(b+31,LoadAConst(1,b+33),length=2)                      # ld a,1
 p.hook(b+33,Sm83StoreAHighImmediate(0xd5,b+35),length=2)
 p.hook(b+38,Sm83LoadAHighImmediate(0xb4,b+40),length=2)       # ldh a,[hJoyHeld]
 p.hook(b+40,Sm83BitRegister(0,'a',b+42),length=2)             # bit B_PAD_A,a
 p.hook(b+42,Fork(b+46,b+44,6,False),length=2)                 # jr z,.checkBButton
 p.hook(b+46,Sm83BitRegister(1,'a',b+48),length=2)             # bit B_PAD_B,a
 p.hook(b+48,Fork(b+55,b+50,6,False),length=2)                 # jr z,.buttonsNotPressed
 p.hook(b+50,DelayFrameSite(b+53),length=3)                    # call DelayFrame
 p.hook(b+53,Jmp(b+60),length=2)                               # jr .done (chain keeper)
 p.hook(b+55,Sm83LoadAHighImmediate(0xd5,b+57),length=2)       # ldh a,[hFrameCounter]
 p.hook(b+57,Sm83AndRegisterH('a',b+58),length=1)              # and a
 p.hook(b+58,SpinBoundary(),length=2)                          # jr nz,.checkButtons (ISR spin boundary)
 p.hook(b+60,Pop16('b','c',b+61),length=1)
 p.hook(b+61,Pop16('d','e',b+62),length=1)
 p.hook(b+62,Pop16('h','l',b+63),length=1)
 # Joypad homecall wrapper chain (the proved callee executes for real).
 p.hook(jw+0,Sm83LoadAHighImmediate(0xb8,jw+2),length=2)
 p.hook(jw+2,PushAF(jw+3),length=1)
 p.hook(jw+3,LoadAConst(JOYPAD_BANK,jw+5),length=2)
 p.hook(jw+5,Sm83StoreAHighImmediate(0xb8,jw+7),length=2)
 p.hook(jw+7,Sm83StoreAImmediate(R_ROMB,jw+10),length=3)
 p.hook(jw+13,PopAF(jw+14),length=1)
 p.hook(jw+14,Sm83StoreAHighImmediate(0xb8,jw+16),length=2)
 p.hook(jw+16,Sm83StoreAImmediate(R_ROMB,jw+19),length=3)
 p.hook(q+0,Sm83LoadAHighImmediate(0xf8,q+2),length=1)
 p.hook(q+2,Sm83CpImmediate(PAD_BUTTONS,q+4),length=2)
 p.hook(q+4,Fork(jret,q+7,6,False,jspr),length=3)
 p.hook(q+8,Sm83LoadAHighImmediate(0xb1,q+10),length=2)
 p.hook(q+14,Sm83StoreAHighImmediate(0xb2,q+16),length=2)
 p.hook(q+18,Sm83StoreAHighImmediate(0xb3,q+20),length=2)
 p.hook(q+21,Sm83StoreAHighImmediate(0xb1,q+23),length=2)
 p.hook(q+23,Sm83LoadAImmediate(W_STATUSFLAGS5,q+26),length=3)
 p.hook(q+26,Sm83BitRegister(BIT_DISABLE_JOYPAD,'a',q+28),length=2)
 p.hook(q+28,Fork(q+52,q+30,6,True),length=2)
 p.hook(q+30,Sm83LoadAHighImmediate(0xb1,q+32),length=2)
 p.hook(q+32,Sm83StoreAHighImmediate(0xb4,q+34),length=2)
 p.hook(q+34,Sm83LoadAImmediate(W_JOYIGNORE,q+37),length=3)
 p.hook(q+37,Sm83AndRegister('a',q+38),length=1)
 p.hook(q+38,Fork(jret,q+39,6,False,jspr),length=1)
 p.hook(q+41,Sm83LoadAHighImmediate(0xb4,q+43),length=2)
 p.hook(q+44,Sm83StoreAHighImmediate(0xb4,q+46),length=2)
 p.hook(q+46,Sm83LoadAHighImmediate(0xb3,q+48),length=2)
 p.hook(q+49,Sm83StoreAHighImmediate(0xb3,q+51),length=2)
 p.hook(q+51,DoRet(jret,jspr),length=1)
 p.hook(q+53,Sm83StoreAHighImmediate(0xb4,q+55),length=2)
 p.hook(q+55,Sm83StoreAHighImmediate(0xb3,q+57),length=2)
 p.hook(q+57,Sm83StoreAHighImmediate(0xb2,q+59),length=2)
 p.hook(q+59,DoRet(jret,jspr),length=1)
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v,False);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(s);m.explore(find=lambda st:st.addr==RETURN,num_find=64);assert not m.errored and len(m.found)>=7
 out=[]
 for x in m.found:
  ar=assembly_registers(x)
  out.append(E(**{**{k:v for k,v in ar.items() if k not in ('h','l')},'hl':x.regs.hl},frame=x.memory.load(H_FRAME_COUNTER,1),joy_input=x.memory.load(H_JOYINPUT,1),joy_last=x.memory.load(H_JOYLAST,1),joy_released=x.memory.load(H_JOYRELEASED,1),joy_pressed=x.memory.load(H_JOYPRESSED,1),joy_held=x.memory.load(H_JOYHELD,1),bank=x.memory.load(BANK_ADDR,1),romb=x.memory.load(R_ROMB,1),status=x.memory.load(W_STATUSFLAGS5,1),ignore=x.memory.load(W_JOYIGNORE,1),lpf=x.memory.load(W_LETTER_PRINTING_DELAY_FLAGS,1),woptions=x.memory.load(W_OPTIONS,1),constraints=tuple(x.solver.constraints)))
 return out
def native(v):
 p=angr.Project(ELF,auto_load_libs=False)
 f=p.loader.find_symbol('port_print_letter_delay');assert f
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v,True)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)>=4
 out=[]
 for x in m.deadended:
  nr=native_registers(x,NS)
  out.append(E(**{**{k:v for k,v in nr.items() if k not in ('h','l')},'hl':claripy.Concat(nr['h'],nr['l'])},frame=x.memory.load(NM+H_FRAME_COUNTER,1),joy_input=x.memory.load(NM+H_JOYINPUT,1),joy_last=x.memory.load(NM+H_JOYLAST,1),joy_released=x.memory.load(NM+H_JOYRELEASED,1),joy_pressed=x.memory.load(NM+H_JOYPRESSED,1),joy_held=x.memory.load(NM+H_JOYHELD,1),bank=x.memory.load(NM+BANK_ADDR,1),romb=x.memory.load(NM+R_ROMB,1),status=x.memory.load(NM+W_STATUSFLAGS5,1),ignore=x.memory.load(NM+W_JOYIGNORE,1),lpf=x.memory.load(NM+W_LETTER_PRINTING_DELAY_FLAGS,1),woptions=x.memory.load(NM+W_OPTIONS,1),constraints=tuple(x.solver.constraints)))
 return out
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_print_letter_delay_pathwise_equivalence():
 v=inputs('pld');assert_pathwise_equivalent(assembly(v),native(v),('a','f','b','c','d','e','hl','frame','joy_input','joy_last','joy_released','joy_pressed','joy_held','bank','romb','status','ignore','lpf','woptions'))
