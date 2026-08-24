from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
from verification.harness.sm83_shims import Sm83AddRegister,Sm83AndRegister,Sm83LoadAHighImmediate,Sm83LoadAImmediate,Sm83StoreAAtHlIncrement,Sm83StoreAHighImmediate,Sm83SwapRegister
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;STACK=0xd000;RETURN=0xffff;DONE=0xefff;SNAP=8*len(REGISTERS)
DIV=0xff95;DVS=0xff99;PDY=0xcd6d;TPY=0xcce5;LV_B=0xd022;LV_E=0xcff3;TURN=0xfff3;BANK=0x0b
EXPECTED=bytes.fromhex('af216dcd22f0f3a7fa22d02803faf3cf87e098afe095e096e0973e64e0990604cdb938f09822f099e0983e0ae0990604cdb938f098cb3747f099807711e7cc0e033e0bcd6d3e21047fc3493c')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
 pd0:claripy.ast.BV;pd1:claripy.ast.BV;pd2:claripy.ast.BV
 tm0:claripy.ast.BV;tm1:claripy.ast.BV;tm2:claripy.ast.BV
 dv0:claripy.ast.BV;dv1:claripy.ast.BV;dv2:claripy.ast.BV;dv3:claripy.ast.BV;dvs:claripy.ast.BV
 lvb:claripy.ast.BV;lve:claripy.ast.BV;turn:claripy.ast.BV
 ib0:claripy.ast.BV;ib1:claripy.ast.BV;ib2:claripy.ast.BV;ib3:claripy.ast.BV
 constraints:tuple[claripy.ast.Bool,...]
MEM=(('pd0',PDY),('pd1',PDY+1),('pd2',PDY+2),('tm0',TPY),('tm1',TPY+1),('tm2',TPY+2),('dv0',DIV),('dv1',DIV+1),('dv2',DIV+2),('dv3',DIV+3),('dvs',DVS),('lvb',LV_B),('lve',LV_E),('turn',TURN))
class ACall(angr.SimProcedure):
 """Composition boundary. Divide sites: the proven wrapper contract keeps
 F/B/C/D/E/H/L and hands back A = $0b (the current bank byte) while the
 quotient/remainder bytes are its own proven domain (arbitrary here).
 Predef/PrintText sites: arbitrary matching proven transitions."""
 def __init__(self,site:int,next_address:int|None,kind:str)->None:
  super().__init__();self._site=site;self._next=DONE if next_address is None else next_address;self._kind=kind
 def run(self):
  k=self._site
  r=assembly_registers(self.state)
  if self._kind=='divide':
   mem=claripy.Concat(*(self.state.memory.load(DIV+i,1) for i in range(5)))
   self.state.globals[f'ib{k}']=claripy.Concat(*(r[x] for x in REGISTERS),mem)
  else:
   self.state.globals[f'ib{k}']=claripy.Concat(*(r[x] for x in REGISTERS))
  if self._kind=='divide':
   # Proven Divide wrapper contract: F/B/C/D/E/H/L preserved, A = bank byte.
   self.state.regs.a=claripy.BVV(BANK,8)
   for i in range(5):self.state.memory.store(DIV+i,self.state.globals[f'om{k}_{i}'])
  else:
   for x in REGISTERS:
    v=self.state.globals[f'out{k}_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
   if self._kind=='predef':
    for i in range(3):self.state.memory.store(TPY+i,self.state.globals[f'om{k}_{i}'])
  self.jump(self._next)
class NCall(angr.SimProcedure):
 def __init__(self,kind:str,site:int|None=None)->None:
  super().__init__();self._kind=kind;self._site=site
 def run(self,s,m):
  if self._kind=='divide':
   k=self.state.globals['div_site'];self.state.globals['div_site']+=1  # first call = site 0, second = site 1
  else:
   k=self._site
  if self._kind=='divide':
   # struct: registers at s+0..7, dividend s+8..11, divisor s+12
   regs=self.state.memory.load(s,8);mem=self.state.memory.load(s+8,5)
   self.state.globals[f'ib{k}']=claripy.Concat(regs,mem)
   self.state.memory.store(s,claripy.Concat(claripy.BVV(BANK,8),*(self.state.memory.load(s+1+i,1) for i in range(7))))
   self.state.memory.store(s+8,claripy.Concat(*(self.state.globals[f'om{k}_{i}'] for i in range(5))))
  else:
   self.state.globals[f'ib{k}']=self.state.memory.load(s,8)
   self.state.memory.store(s,claripy.Concat(*(self.state.globals[f'out{k}_{x}'] for x in REGISTERS)))
   if self._kind=='predef':
    for i in range(3):self.state.memory.store(m+TPY+i,self.state.globals[f'om{k}_{i}'])
class Sm83LoadABytePreserveF(angr.SimProcedure):
 """SM83 `LD A,n` (3E): A := immediate; flags unchanged. The shared
 Sm83LoadAFromImmediate shim clears F, which is wrong when later call
 boundaries capture live flags."""
 def __init__(self,immediate_address:int,next_address:int)->None:
  super().__init__();self._imm=immediate_address;self._next=next_address
 def run(self):
  self.state.regs.a=self.state.memory.load(self._imm,1);self.jump(self._next)
class Sm83XorA(angr.SimProcedure):
 """SM83 `XOR A` (AF): A := 0, Z set, N/H/C clear. The z80 p-code backend
 models AF with wrong flags."""
 def __init__(self,next_address:int)->None:
  super().__init__();self._next=next_address
 def run(self):
  self.state.regs.a=claripy.BVV(0,8);self.state.regs.f=claripy.BVV(0x40,8);self.jump(self._next)
def inputs(p):
 v=symbolic_registers(p)
 for name,addr in MEM:v[name]=claripy.BVS(f'{p}_{name}',8)
 for k in range(4):
  for x in REGISTERS:v[f'out{k}_{x}']=claripy.Concat(claripy.BVS(f'{p}_out{k}_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(f'{p}_out{k}_{x}',8)
  n=5 if k in (0,1) else (3 if k==2 else 0)
  for i in range(n):v[f'om{k}_{i}']=claripy.BVS(f'{p}_om{k}_{i}',8)
 return v
def setup(s,v,native:bool):
 o=NM if native else 0
 for name,addr in MEM:s.memory.store(o+addr,v[name])
 for k in range(4):
  for x in REGISTERS:s.globals[f'out{k}_{x}']=v[f'out{k}_{x}']
  n=5 if k in (0,1) else (3 if k==2 else 0)
  for i in range(n):s.globals[f'om{k}_{i}']=v[f'om{k}_{i}']
def assembly(v):
 l=symbol_location(SYMS,'PayDayEffect_');pt=symbol_location(SYMS,'PrintText')
 assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+0,Sm83XorA(b+1),length=1)                      # xor a
 p.hook(b+4,Sm83StoreAAtHlIncrement(b+5),length=1)       # ld [hli],a
 p.hook(b+5,Sm83LoadAHighImmediate(0xf3,b+7),length=2)   # ldh a,[hWhoseTurn]
 p.hook(b+7,Sm83AndRegister('a',b+8),length=1)           # and a
 p.hook(b+8,Sm83LoadAImmediate(0xd022,b+11),length=3)    # ld a,[wBattleMonLevel]
 p.hook(b+13,Sm83LoadAImmediate(0xcff3,b+16),length=3)   # ld a,[wEnemyMonLevel]
 p.hook(b+16,Sm83AddRegister('a',b+17),length=1)         # add a
 p.hook(b+17,Sm83StoreAHighImmediate(0x98,b+19),length=2)
 p.hook(b+19,Sm83XorA(b+20),length=1)                    # xor a
 p.hook(b+20,Sm83StoreAHighImmediate(0x95,b+22),length=2)
 p.hook(b+22,Sm83StoreAHighImmediate(0x96,b+24),length=2)
 p.hook(b+24,Sm83StoreAHighImmediate(0x97,b+26),length=2)
 p.hook(b+26,Sm83LoadABytePreserveF(b+27,b+28),length=2) # ld a,$64
 p.hook(b+28,Sm83StoreAHighImmediate(0x99,b+30),length=2)
 p.hook(b+32,ACall(0,b+35,'divide'),length=3)            # call Divide
 p.hook(b+35,Sm83LoadAHighImmediate(0x98,b+37),length=2)
 p.hook(b+37,Sm83StoreAAtHlIncrement(b+38),length=1)     # ld [hli],a
 p.hook(b+38,Sm83LoadAHighImmediate(0x99,b+40),length=2)
 p.hook(b+40,Sm83StoreAHighImmediate(0x98,b+42),length=2)
 p.hook(b+42,Sm83LoadABytePreserveF(b+43,b+44),length=2) # ld a,$0a
 p.hook(b+44,Sm83StoreAHighImmediate(0x99,b+46),length=2)
 p.hook(b+48,ACall(1,b+51,'divide'),length=3)            # call Divide
 p.hook(b+51,Sm83LoadAHighImmediate(0x98,b+53),length=2)
 p.hook(b+53,Sm83SwapRegister('a',b+55),length=2)        # swap a
 p.hook(b+56,Sm83LoadAHighImmediate(0x99,b+58),length=2)
 p.hook(b+58,Sm83AddRegister('b',b+59),length=1)         # add b
 p.hook(b+65,Sm83LoadABytePreserveF(b+66,b+67),length=2) # ld a,$0b
 p.hook(b+67,ACall(2,b+70,'predef'),length=3)            # call Predef (AddBCDPredef)
 p.hook(pt.address,ACall(3,None,'tail'))                 # jp PrintText tail
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v,False);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(s);m.explore(find=lambda st:st.addr==DONE,num_find=64);assert not m.errored and len(m.found)==2  # one terminal path per turn value
 return [E(**assembly_registers(x),**{n:x.memory.load(a,1) for n,a in MEM},**{f'ib{k}':x.globals[f'ib{k}'] for k in range(4)},constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False)
 syms={n:p.loader.find_symbol(s) for n,s in (('port_divide_wrapper','port_divide_wrapper'),('port_add_bcd_predef','port_add_bcd_predef'),('port_print_text','port_print_text'))}
 assert all(syms.values())
 p.hook(syms['port_divide_wrapper'].rebased_addr,NCall('divide'))
 p.hook(syms['port_add_bcd_predef'].rebased_addr,NCall('predef',2))
 p.hook(syms['port_print_text'].rebased_addr,NCall('tail',3))
 f=p.loader.find_symbol('port_pay_day_effect');assert f
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v,True);s.globals['div_site']=0
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1
 return [E(**native_registers(x,NS),**{n:x.memory.load(NM+a,1) for n,a in MEM},**{f'ib{k}':x.globals[f'ib{k}'] for k in range(4)},constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_pay_day_effect_pathwise_equivalence():
 v=inputs('pay_day_effect');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,*(n for n,_ in MEM),'ib0','ib1','ib2','ib3'))
