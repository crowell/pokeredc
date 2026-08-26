from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AndRegister,Sm83BitRegister,Sm83CpImmediate,Sm83LoadAHighImmediate,Sm83LoadAImmediate,Sm83StoreAHighImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;STACK=0xd000;RETURN=0xffff
BANK_ADDR=0xffb8;R_ROMB=0x2000;H_JOYINPUT=0xfff8;H_JOYLAST=0xffb1;H_JOYRELEASED=0xffb2;H_JOYPRESSED=0xffb3;H_JOYHELD=0xffb4;W_STATUSFLAGS5=0xd730;W_JOYIGNORE=0xcd6b
PAD_BUTTONS=0x0f;BIT_DISABLE_JOYPAD=5;JOYPAD_BANK=3
EXPECTED=bytes.fromhex('f0b8f53e03e0b8ea0020cd0040f1e0b8ea0020c9')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;hl:claripy.ast.BV
 bank:claripy.ast.BV;romb:claripy.ast.BV;joy_input:claripy.ast.BV;joy_last:claripy.ast.BV;joy_released:claripy.ast.BV;joy_pressed:claripy.ast.BV;joy_held:claripy.ast.BV;status:claripy.ast.BV;ignore:claripy.ast.BV
 constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 v=symbolic_registers(p)
 for name in ('bank','romb','joy_input','joy_last','joy_released','joy_pressed','joy_held','status','ignore'):v[name]=claripy.BVS(f'{p}_{name}',8)
 return v
def setup(s,v,native:bool):
 o=NM if native else 0
 for name,addr in (('bank',BANK_ADDR),('romb',R_ROMB),('joy_input',H_JOYINPUT),('joy_last',H_JOYLAST),('joy_released',H_JOYRELEASED),('joy_pressed',H_JOYPRESSED),('joy_held',H_JOYHELD),('status',W_STATUSFLAGS5),('ignore',W_JOYIGNORE)):s.memory.store(o+addr,v[name])
class PushAF(angr.SimProcedure):
 """SM83 `PUSH AF`: (SP-1):=A, (SP-2):=F, SP:=SP-2."""
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  sp=self.state.solver.eval(self.state.regs.sp)
  self.state.memory.store(sp-1,self.state.regs.a);self.state.memory.store(sp-2,self.state.regs.f)
  self.state.regs.sp=claripy.BVV(sp-2,16);self.jump(self._n)
class PopAF(angr.SimProcedure):
 """SM83 `POP AF`: F:=[SP], A:=[SP+1], SP:=SP+2."""
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  sp=self.state.solver.eval(self.state.regs.sp)
  self.state.regs.f=self.state.memory.load(sp,1);self.state.regs.a=self.state.memory.load(sp+1,1)
  self.state.regs.sp=claripy.BVV(sp+2,16);self.jump(self._n)
class LoadAConst(angr.SimProcedure):
 """SM83 `LD A,n`."""
 def __init__(self,val:int,n:int)->None:
  super().__init__();self._v=val;self._n=n
 def run(self):
  self.state.regs.a=claripy.BVV(self._v,8);self.jump(self._n)
class Fork(angr.SimProcedure):
 """Fork a conditional branch whose taken side returns to the wrapper's
 post-call address with the call frame popped (the bundled Z80 SLEIGH
 does not fork conditional JR/JP/RET)."""
 def __init__(self,taken:int,fall:int,bit:int,invert:bool)->None:
  super().__init__();self._taken=taken;self._fall=fall;self._bit=bit;self._invert=invert
 def run(self):
  f=self.state.regs.f;flag=(f>>self._bit)&1
  cond=(flag==0) if self._invert else (flag==1)
  ts=self.state.copy();fs=self.state.copy()
  ts.solver.add(cond);fs.solver.add(claripy.Not(cond))
  ts.regs.ip=claripy.BVV(self._taken,16);fs.regs.ip=claripy.BVV(self._fall,16)
  ts.regs.sp=claripy.BVV(STACK-2,16)
  self.inhibit_autoret=True
  self.successors.add_successor(ts,self._taken,cond,'Ijk_Boring')
  self.successors.add_successor(fs,self._fall,claripy.Not(cond),'Ijk_Boring')
class DoRet(angr.SimProcedure):
 """Unconditional return from the called callee to the wrapper."""
 def __init__(self,ret:int)->None:
  super().__init__();self._ret=ret
 def run(self):
  self.inhibit_autoret=True;self.state.regs.sp=claripy.BVV(STACK-2,16);self.jump(self._ret)
def assembly(v):
 w=symbol_location(SYMS,'Joypad');q=symbol_location(SYMS,'_Joypad')
 assert w.bank==0 and q.bank==JOYPAD_BANK
 assert linked_bytes(ROM,w,len(EXPECTED))==EXPECTED
 assert q.address==0x4000
 p=angr.Project(rom_window(ROM,JOYPAD_BANK),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':w.address});b=w.address;q=q.address;ret=b+13
 # Wrapper chain: every instruction boundary is hooked so each later shim
 # starts its own block (the p-code engine only fires hooks at block starts).
 p.hook(b+0,Sm83LoadAHighImmediate(0xb8,b+2),length=2)          # ldh a,[hLoadedROMBank]
 p.hook(b+2,PushAF(b+3),length=1)                               # push af
 p.hook(b+3,LoadAConst(JOYPAD_BANK,b+5),length=2)               # ld a,BANK(_Joypad)
 p.hook(b+5,Sm83StoreAHighImmediate(0xb8,b+7),length=2)         # ldh [hLoadedROMBank],a
 p.hook(b+7,Sm83StoreAImmediate(R_ROMB,b+10),length=3)          # ld [rROMB],a
 p.hook(b+13,PopAF(b+14),length=1)                              # pop af
 p.hook(b+14,Sm83StoreAHighImmediate(0xb8,b+16),length=2)       # ldh [hLoadedROMBank],a
 p.hook(b+16,Sm83StoreAImmediate(R_ROMB,b+19),length=3)         # ld [rROMB],a
 # _Joypad interior (the proved callee executes for real, with its
 # established per-instruction shim chain).
 p.hook(q+0,Sm83LoadAHighImmediate(0xf8,q+2),length=1)          # ldh a,[hJoyInput]
 p.hook(q+2,Sm83CpImmediate(PAD_BUTTONS,q+4),length=2)          # cp PAD_BUTTONS
 p.hook(q+4,Fork(ret,q+7,6,False),length=3)                     # jp z,TrySoftReset (modeled early return)
 p.hook(q+8,Sm83LoadAHighImmediate(0xb1,q+10),length=2)         # ldh a,[hJoyLast]
 p.hook(q+14,Sm83StoreAHighImmediate(0xb2,q+16),length=2)       # ldh [hJoyReleased],a
 p.hook(q+18,Sm83StoreAHighImmediate(0xb3,q+20),length=2)       # ldh [hJoyPressed],a
 p.hook(q+21,Sm83StoreAHighImmediate(0xb1,q+23),length=2)       # ldh [hJoyLast],a
 p.hook(q+23,Sm83LoadAImmediate(W_STATUSFLAGS5,q+26),length=3)  # ld a,[wStatusFlags5]
 p.hook(q+26,Sm83BitRegister(BIT_DISABLE_JOYPAD,'a',q+28),length=2)
 p.hook(q+28,Fork(q+52,q+30,6,True),length=2)                   # jr nz,DiscardButtonPresses
 p.hook(q+30,Sm83LoadAHighImmediate(0xb1,q+32),length=2)        # ldh a,[hJoyLast]
 p.hook(q+32,Sm83StoreAHighImmediate(0xb4,q+34),length=2)       # ldh [hJoyHeld],a
 p.hook(q+34,Sm83LoadAImmediate(W_JOYIGNORE,q+37),length=3)     # ld a,[wJoyIgnore]
 p.hook(q+37,Sm83AndRegister('a',q+38),length=1)                # and a
 p.hook(q+38,Fork(ret,q+39,6,False),length=1)                   # ret z
 p.hook(q+41,Sm83LoadAHighImmediate(0xb4,q+43),length=2)        # ldh a,[hJoyHeld]
 p.hook(q+44,Sm83StoreAHighImmediate(0xb4,q+46),length=2)       # ldh [hJoyHeld],a
 p.hook(q+46,Sm83LoadAHighImmediate(0xb3,q+48),length=2)        # ldh a,[hJoyPressed]
 p.hook(q+49,Sm83StoreAHighImmediate(0xb3,q+51),length=2)       # ldh [hJoyPressed],a
 p.hook(q+51,DoRet(ret),length=1)                               # ret
 p.hook(q+53,Sm83StoreAHighImmediate(0xb4,q+55),length=2)       # ldh [hJoyHeld],a (discard)
 p.hook(q+55,Sm83StoreAHighImmediate(0xb3,q+57),length=2)       # ldh [hJoyPressed],a
 p.hook(q+57,Sm83StoreAHighImmediate(0xb2,q+59),length=2)       # ldh [hJoyReleased],a
 p.hook(q+59,DoRet(ret),length=1)                               # ret
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v,False);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(s);m.explore(find=lambda st:st.addr==RETURN,num_find=64);assert not m.errored and len(m.found)==4
 out=[]
 for x in m.found:
  ar=assembly_registers(x)
  out.append(E(**{**{k:v for k,v in ar.items() if k not in ('h','l')},'hl':x.regs.hl},bank=x.memory.load(BANK_ADDR,1),romb=x.memory.load(R_ROMB,1),joy_input=x.memory.load(H_JOYINPUT,1),joy_last=x.memory.load(H_JOYLAST,1),joy_released=x.memory.load(H_JOYRELEASED,1),joy_pressed=x.memory.load(H_JOYPRESSED,1),joy_held=x.memory.load(H_JOYHELD,1),status=x.memory.load(W_STATUSFLAGS5,1),ignore=x.memory.load(W_JOYIGNORE,1),constraints=tuple(x.solver.constraints)))
 return out
def native(v):
 p=angr.Project(ELF,auto_load_libs=False)
 f=p.loader.find_symbol('port_joypad_homecall');assert f
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v,True)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==4
 out=[]
 for x in m.deadended:
  nr=native_registers(x,NS)
  out.append(E(**{**{k:v for k,v in nr.items() if k not in ('h','l')},'hl':claripy.Concat(nr['h'],nr['l'])},bank=x.memory.load(NM+BANK_ADDR,1),romb=x.memory.load(NM+R_ROMB,1),joy_input=x.memory.load(NM+H_JOYINPUT,1),joy_last=x.memory.load(NM+H_JOYLAST,1),joy_released=x.memory.load(NM+H_JOYRELEASED,1),joy_pressed=x.memory.load(NM+H_JOYPRESSED,1),joy_held=x.memory.load(NM+H_JOYHELD,1),status=x.memory.load(NM+W_STATUSFLAGS5,1),ignore=x.memory.load(NM+W_JOYIGNORE,1),constraints=tuple(x.solver.constraints)))
 return out
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_joypad_homecall_pathwise_equivalence():
 v=inputs('joywrap');assert_pathwise_equivalent(assembly(v),native(v),('a','f','b','c','d','e','hl','bank','romb','joy_input','joy_last','joy_released','joy_pressed','joy_held','status','ignore'))
