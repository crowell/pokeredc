from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83AddImmediate, Sm83AddRegister, Sm83AndRegister, Sm83CpRegister, Sm83IncRegister, Sm83LoadAImmediate, Sm83OrRegister, Sm83StoreAImmediate, Sm83SwapRegister, Sm83XorA

ROOT=Path(__file__).resolve().parents[2]; ELF=ROOT/'verification/build/ports.elf'; ROM=ROOT/'pokered.gbc'; SYMS=ROOT/'pokered.sym'
NS=0x100000; NM=0x200000; DONE=0xefff
CUR_X=0xd0a1; CUR_Y=0xd0a2; WIDTH=0xd0a3; HEIGHT=0xd0a4; FLIPPED=0xd0aa
OUT=0xd0ad; CACHED=0xd0af; TABLE0=0xd0b1; TABLE1=0xd0b3
TABLE_START=0x27a7; TABLE_SIZE=32; BUFFER_SIZE=392
EXPECTED=bytes.fromhex('afeaa1d0eaa2d0cd9728faaad0a7280821b72711bf27180621a72711af277deab1d07ceab2d07beab3d07aeab4d01e00faadd06ffaaed0677e47cb37e60fcd6d27cb375778e60fcd6d27b247faadd06ffaaed0677877faa4d085300124eaadd07ceaaed0faa1d0c608eaa1d047faa3d0b820bdaf5feaa1d0faa2d03ceaa2d047faa4d0b8280efaafd06ffab0d06723cd9728189cafeaa2d0c9')
GLOBALS=(CUR_X,CUR_Y,WIDTH,HEIGHT,FLIPPED,OUT,OUT+1,CACHED,CACHED+1,TABLE0,TABLE0+1,TABLE1,TABLE1+1)
TABLE_BYTES=linked_bytes(ROM,symbol_location(SYMS,'DecodeNybble0Table'),TABLE_SIZE)

@dataclass(frozen=True)
class E:
 a:claripy.ast.BV; f:claripy.ast.BV; b:claripy.ast.BV; c:claripy.ast.BV; d:claripy.ast.BV; e:claripy.ast.BV; h:claripy.ast.BV; l:claripy.ast.BV
 memory:claripy.ast.BV; store_calls:claripy.ast.BV; decode_calls:claripy.ast.BV; constraints:tuple[claripy.ast.Bool,...]

def inputs(tag:str):
 v=symbolic_registers(tag); v['flipped']=claripy.BVS(tag+'_flipped',8); v['buffer']=claripy.BVS(tag+'_buffer',(BUFFER_SIZE+2)*8)
 for i,a in enumerate(GLOBALS): v[f'g{i}']=claripy.BVS(f'{tag}_g{i}',8)
 return v

def setup(s,v,base:int,start:int,dimension:int):
 s.memory.store(base+start-1,v['buffer']); s.memory.store(base+FLIPPED,v['flipped'])
 for i,a in enumerate(GLOBALS):
  if a not in (FLIPPED,WIDTH,HEIGHT): s.memory.store(base+a,v[f'g{i}'])
 s.memory.store(base+WIDTH,claripy.BVV(dimension,8)); s.memory.store(base+HEIGHT,claripy.BVV(dimension,8))
 tables=linked_bytes(ROM,symbol_location(SYMS,'DecodeNybble0Table'),TABLE_SIZE)
 s.memory.store(base+TABLE_START,claripy.BVV(tables,TABLE_SIZE*8)); s.globals['store_calls']=claripy.BVV(0,16); s.globals['decode_calls']=claripy.BVV(0,16)

def memory(s,base:int,start:int):
 return claripy.Concat(s.memory.load(base+start-1,BUFFER_SIZE+2),*(s.memory.load(base+a,1) for a in GLOBALS))

def store_transition_asm(s):
 s.globals['store_calls']+=1; s.regs.a=s.regs.l; s.memory.store(OUT,s.regs.a); s.memory.store(CACHED,s.regs.a); s.regs.a=s.regs.h; s.memory.store(OUT+1,s.regs.a); s.memory.store(CACHED+1,s.regs.a)

def assert_decode_transform_matches_tables():
 for flip in (0,1):
  for previous in range(16):
   for encoded in range(16):
    normal=((encoded&1)^((-((encoded>>1)&1))&3)^((-((encoded>>2)&1))&7)^((-((encoded>>3)&1))&0xf))&0xf
    flipped=((-(encoded&1)&8)^((-((encoded>>1)&1))&0xc)^((-((encoded>>2)&1))&0xe)^((-((encoded>>3)&1))&0xf))&0xf
    decoded=(flipped if flip else normal)^(0xf if previous&(8 if flip else 1) else 0)
    offset=(16 if flip else 0)+(8 if previous&(8 if flip else 1) else 0)+(encoded>>1)
    expected=(TABLE_BYTES[offset]>>(0 if encoded&1 else 4))&0xf
    assert decoded==expected

def decode_transition_asm(s):
 s.globals['decode_calls']+=1; encoded=s.regs.a; previous=s.regs.e; index=claripy.LShR(encoded,1); bit=encoded&1
 flipped=s.memory.load(FLIPPED,1); t0=claripy.Concat(s.memory.load(TABLE0+1,1),s.memory.load(TABLE0,1)); t1=claripy.Concat(s.memory.load(TABLE1+1,1),s.memory.load(TABLE1,1))
 use1=claripy.If(flipped!=0,(previous&8)!=0,(previous&1)!=0); ptr=claripy.If(use1,t1,t0)+claripy.ZeroExt(8,index)
 mask=lambda value:claripy.If(value!=0,claripy.BVV(0xff,8),claripy.BVV(0,8)); normal=(encoded&1)^(mask(claripy.LShR(encoded,1)&1)&3)^(mask(claripy.LShR(encoded,2)&1)&7)^(mask(claripy.LShR(encoded,3)&1)&0xf); flipped_value=(mask(encoded&1)&8)^(mask(claripy.LShR(encoded,1)&1)&0xc)^(mask(claripy.LShR(encoded,2)&1)&0xe)^(mask(claripy.LShR(encoded,3)&1)&0xf)
 flip_mask=mask(flipped); decoded=(normal&~flip_mask)|(flipped_value&flip_mask); previous_mask=(1&~flip_mask)|(8&flip_mask); decoded^=mask(previous&previous_mask)&0xf; fetched=(decoded<<4)|decoded
 result=claripy.If(bit!=0,fetched&0xf,claripy.LShR(fetched,4)&0xf)
 s.regs.c=bit; s.regs.l=index; s.regs.a=flipped; s.regs.e=index; s.regs.h=ptr[15:8]; s.regs.l=ptr[7:0]; s.regs.a=result; s.regs.e=result; s.regs.f=claripy.If(result==0,claripy.BVV(0x50,8),claripy.BVV(0x10,8))

class StoreAsm(angr.SimProcedure):
 def __init__(self,n): super().__init__(); self.n=n
 def run(self): store_transition_asm(self.state); self.jump(self.n)
class DecodeAsm(angr.SimProcedure):
 def __init__(self,n): super().__init__(); self.n=n
 def run(self): decode_transition_asm(self.state); self.jump(self.n)
class StoreNative(angr.SimProcedure):
 def run(self,p):
  self.state.globals['store_calls']+=1; a=self.state.memory.load(p+7,1); self.state.memory.store(p,a); self.state.memory.store(p+8,a); self.state.memory.store(p+9,a); a=self.state.memory.load(p+6,1); self.state.memory.store(p,a); self.state.memory.store(p+10,a); self.state.memory.store(p+11,a)
class DecodeNative(angr.SimProcedure):
 def run(self,p):
  self.state.globals['decode_calls']+=1; r=lambda o:self.state.memory.load(p+o,1); encoded=r(0); previous=r(5); index=claripy.LShR(encoded,1); bit=encoded&1; flipped=r(8); t0=claripy.Concat(r(10),r(9)); t1=claripy.Concat(r(12),r(11)); use1=claripy.If(flipped!=0,(previous&8)!=0,(previous&1)!=0); ptr=claripy.If(use1,t1,t0)+claripy.ZeroExt(8,index); fetched=r(13); result=claripy.If(bit!=0,fetched&0xf,claripy.LShR(fetched,4)&0xf)
  self.state.memory.store(p+3,bit); self.state.memory.store(p+7,ptr[7:0]); self.state.memory.store(p+6,ptr[15:8]); self.state.memory.store(p,result); self.state.memory.store(p+5,result); self.state.memory.store(p+1,claripy.If(result==0,claripy.BVV(0xa0,8),claripy.BVV(0x20,8)))
class AndA(angr.SimProcedure):
 def __init__(self,n): super().__init__(); self.n=n
 def run(self): self.state.regs.f=claripy.If(self.state.regs.a==0,claripy.BVV(0x50,8),claripy.BVV(0x10,8)); self.jump(self.n)
class AndImm(angr.SimProcedure):
 def __init__(self,x,n): super().__init__(); self.x=x; self.n=n
 def run(self): self.state.regs.a&=self.x; self.state.regs.f=claripy.If(self.state.regs.a==0,claripy.BVV(0x50,8),claripy.BVV(0x10,8)); self.jump(self.n)
class Fork(angr.SimProcedure):
 def __init__(self,bit,set_,t,f): super().__init__(); self.bit=bit; self.set=set_; self.t=t; self.f=f
 def run(self):
  flag=((self.state.regs.f>>self.bit)&1)==1; cond=flag if self.set else claripy.Not(flag); a=self.state.copy(); b=self.state.copy(); a.solver.add(cond); b.solver.add(claripy.Not(cond)); a.regs.ip=self.t; b.regs.ip=self.f; self.inhibit_autoret=True; self.successors.add_successor(a,self.t,cond,'Ijk_Boring'); self.successors.add_successor(b,self.f,claripy.Not(cond),'Ijk_Boring')
class Jump(angr.SimProcedure):
 def __init__(self,n): super().__init__(); self.n=n
 def run(self): self.jump(self.n)

def assembly(v,start,dimension):
 l=symbol_location(SYMS,'SpriteDifferentialDecode'); end=symbol_location(SYMS,'DifferentialDecodeNybble'); assert end.address-l.address==len(EXPECTED) and linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,0),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address}); b=l.address
 p.hook(b,Sm83XorA(b+1),length=1)
 for off,addr,n in ((1,CUR_X,4),(4,CUR_Y,7),(31,TABLE0,34),(35,TABLE0+1,38),(39,TABLE1,42),(43,TABLE1+1,46),(93,OUT,96),(97,OUT+1,100),(105,CUR_X,108),(117,CUR_X,120),(124,CUR_Y,127),(149,CUR_Y,152)): p.hook(b+off,Sm83StoreAImmediate(addr,b+n),length=n-off)
 for off,addr,n in ((10,FLIPPED,13),(48,OUT,51),(52,OUT+1,55),(76,OUT,79),(80,OUT+1,83),(86,HEIGHT,89),(100,CUR_X,103),(109,WIDTH,112),(120,CUR_Y,123),(128,HEIGHT,131),(134,CACHED,137),(138,CACHED+1,141)): p.hook(b+off,Sm83LoadAImmediate(addr,b+n),length=n-off)
 p.hook(b+7,StoreAsm(b+10),length=3); p.hook(b+143,StoreAsm(b+146),length=3); p.hook(b+62,DecodeAsm(b+65),length=3); p.hook(b+71,DecodeAsm(b+74),length=3)
 p.hook(b+13,AndA(b+14),length=1); p.hook(b+14,Fork(6,True,b+24,b+16),length=2); p.hook(b+22,Jump(b+30),length=2)
 p.hook(b+58,Sm83SwapRegister('a',b+60),length=2); p.hook(b+60,AndImm(0xf,b+62),length=2); p.hook(b+65,Sm83SwapRegister('a',b+67),length=2); p.hook(b+69,AndImm(0xf,b+71),length=2); p.hook(b+74,Sm83OrRegister('d',b+75),length=1)
 p.hook(b+89,Sm83AddRegister('l',b+90),length=1); p.hook(b+90,Fork(0,False,b+93,b+92),length=2); p.hook(b+92,Sm83IncRegister('h',b+93),length=1); p.hook(b+103,Sm83AddImmediate(8,b+105),length=2); p.hook(b+112,Sm83CpRegister('b',b+113),length=1); p.hook(b+113,Fork(6,False,b+48,b+115),length=2)
 p.hook(b+115,Sm83XorA(b+116),length=1); p.hook(b+123,Sm83IncRegister('a',b+124),length=1); p.hook(b+131,Sm83CpRegister('b',b+132),length=1); p.hook(b+132,Fork(6,True,b+148,b+134),length=2); p.hook(b+146,Jump(b+48),length=2); p.hook(b+148,Sm83XorA(b+149),length=1); p.hook(b+152,Jump(DONE),length=1)
 s=p.factory.blank_state(addr=b); set_assembly_registers(s,v); s.regs.h=start>>8; s.regs.l=start&255; setup(s,v,0,start,dimension); m=p.factory.simulation_manager(s); m.explore(find=DONE,num_find=2); assert not m.errored and len(m.found)==2
 return [E(**assembly_registers(x),memory=memory(x,0,start),store_calls=x.globals['store_calls'],decode_calls=x.globals['decode_calls'],constraints=tuple(x.solver.constraints)) for x in m.found]

def native(v,start,dimension):
 p=angr.Project(ELF,auto_load_libs=False); f=p.loader.find_symbol('port_sprite_differential_decode'); st=p.loader.find_symbol('port_store_sprite_output_pointer'); dd=p.loader.find_symbol('port_differential_decode_nybble'); assert f and st and dd; p.hook(st.rebased_addr,StoreNative()); p.hook(dd.rebased_addr,DecodeNative()); s=p.factory.call_state(f.rebased_addr,NS,NM); store_native_registers(s,NS,v); s.memory.store(NS+6,claripy.BVV(start>>8,8)); s.memory.store(NS+7,claripy.BVV(start&255,8)); setup(s,v,NM,start,dimension); m=p.factory.simulation_manager(s); m.run(); assert not m.errored and m.deadended
 return [E(**native_registers(x,NS),memory=memory(x,NM,start),store_calls=x.globals['store_calls'],decode_calls=x.globals['decode_calls'],constraints=tuple(x.solver.constraints)) for x in m.deadended]

def assert_case(a,n):
 assert_pathwise_equivalent(a,n,(*REGISTERS,'store_calls','decode_calls'))
 total=BUFFER_SIZE+2+len(GLOBALS)
 for left in a:
  for right in n:
   overlap=claripy.Solver(); overlap.add(left.constraints); overlap.add(right.constraints)
   if not overlap.satisfiable(): continue
   for i in range(total):
    hi=total*8-1-i*8; lo=hi-7; difference=claripy.simplify(left.memory[hi:lo]!=right.memory[hi:lo])
    if claripy.is_false(difference): continue
    if overlap.satisfiable(extra_constraints=(difference,)): raise AssertionError(f'memory byte {i} differs')

@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
@pytest.mark.parametrize(('dimension','start'),((40,0xa188),(40,0xa310),(48,0xa188),(48,0xa310),(56,0xa188),(56,0xa310)),ids=('40-a188','40-a310','48-a188','48-a310','56-a188','56-a310'))
def test_sprite_differential_decode_pathwise_equivalence(dimension,start):
 assert_decode_transform_matches_tables()
 v=inputs(f'sprite_diff_{dimension}_{start:x}'); assert_case(assembly(v,start,dimension),native(v,start,dimension))
