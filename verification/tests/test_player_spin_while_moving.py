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
from verification.harness.sm83_shims import Sm83AddRegister, Sm83CpRegister, Sm83LoadAImmediate, Sm83StoreAImmediate

ROOT=Path(__file__).resolve().parents[2]; ELF=ROOT/'verification/build/ports.elf'; ROM=ROOT/'pokered.gbc'; SYMBOLS=ROOT/'pokered.sym'; NS=0x100000; NM=0x200000; RET=0xffff
DELTA,MAX,DELAY,Y,IMAGE,LIST=0xcd3d,0xcd3e,0xcd3f,0xc104,0xc102,0xcd48
BODY=bytes.fromhex('cd1747fa3dcd4ffa04c181ea04c14ffa3ecdb9c8fa3fcd4fcd393718e3')

@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;state:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]

class Spin(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  s=self.state; h,l=s.regs.h,s.regs.l; s.regs.a=s.memory.load(s.regs.hl,1); s.memory.store(IMAGE,s.regs.a)
  src=claripy.BVV(LIST,16); dst=claripy.BVV(LIST-1,16)
  for _ in range(4): s.memory.store(dst,s.memory.load(src,1));src+=1;dst+=1
  s.regs.a=s.memory.load(LIST-1,1);s.memory.store(LIST+3,s.regs.a);s.regs.b=0;s.regs.c=0;s.regs.d=0xcd;s.regs.e=0x4b;s.regs.h=h;s.regs.l=l;s.regs.f=0x40;self.jump(self.n)
class Delay(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=0;self.state.regs.c=0;self.state.regs.f=0x42;self.jump(self.n)
class ReturnZ(angr.SimProcedure):
 def run(self):
  s=self.state; yes=s.copy();no=s.copy();c=(s.regs.f&0x40)!=0;yes.solver.add(c);no.solver.add(~c);yes.regs.ip=claripy.BVV(RET,16);no.regs.ip=s.regs.ip+1;self.inhibit_autoret=True;self.successors.add_successor(yes,RET,c,'Ijk_Boring');self.successors.add_successor(no,self.addr+1,~c,'Ijk_Boring')
def setup(s,b,v,delta,maxy,y):
 s.memory.store(b+DELTA,claripy.BVV(delta,8));s.memory.store(b+MAX,claripy.BVV(maxy,8));s.memory.store(b+DELAY,claripy.BVV(1,8));s.memory.store(b+Y,claripy.BVV(y,8));
 for i in range(4):s.memory.store(b+LIST+i,v[f'list{i}'])
 s.memory.store(b+IMAGE,v['image']);s.memory.store(b+0xc600,v['source'])
def end(s,n):
 b=NM if n else 0;r=native_registers(s,NS) if n else assembly_registers(s);w=(DELTA,MAX,DELAY,Y,IMAGE,*(LIST+i for i in range(4)));return E(**r,state=claripy.Concat(*(s.memory.load(b+a,1) for a in w)),constraints=tuple(s.solver.constraints))
def asm(v,d,m,y):
 l=symbol_location(SYMBOLS,'PlayerSpinWhileMovingUpOrDown');assert linked_bytes(ROM,l,len(BODY))==BODY;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q,Spin(q+3),length=3);p.hook(q+3,Sm83LoadAImmediate(DELTA,q+6),length=3);p.hook(q+7,Sm83LoadAImmediate(Y,q+10),length=3);p.hook(q+10,Sm83AddRegister('c',q+11),length=1);p.hook(q+11,Sm83StoreAImmediate(Y,q+14),length=3);p.hook(q+15,Sm83LoadAImmediate(MAX,q+18),length=3);p.hook(q+18,Sm83CpRegister('c',q+19),length=1);p.hook(q+19,ReturnZ(),length=1);p.hook(q+20,Sm83LoadAImmediate(DELAY,q+23),length=3);p.hook(q+24,Delay(q+27),length=3);s=p.factory.blank_state(addr=q);set_assembly_registers(s,v);setup(s,0,v,d,m,y);s.regs.h=0xc6;s.regs.l=0;s.regs.sp=0xd000;s.memory.store(0xd000,claripy.BVV(RET,16),endness='Iend_LE');x=p.factory.simulation_manager(s);x.explore(find=RET);assert not x.errored and len(x.found)==1;return [end(x.found[0],False)]
def native(v,d,m,y):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_player_spin_while_moving_up_or_down');assert f;s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);s.memory.store(NS+6,claripy.BVV(0xc6,8));s.memory.store(NS+7,claripy.BVV(0,8));setup(s,NM,v,d,m,y);x=p.factory.simulation_manager(s);x.run();assert not x.errored and len(x.deadended)==1;return [end(x.deadended[0],True)]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),reason='artifacts')
@pytest.mark.parametrize('delta,maxy,y',((0x10,0x3c,0x2c),(0x10,0x3c,0x1c),(0xf0,0xec,0xfc),(0xf0,0xec,0x0c)))
def test_player_spin_while_moving_pathwise_equivalence(delta,maxy,y):
 v=symbolic_registers(f'spinmove_{delta}_{y}');v['source']=claripy.BVS(f'spinmove_source_{delta}_{y}',8);v['image']=claripy.BVS(f'spinmove_image_{delta}_{y}',8)
 for i in range(4):v[f'list{i}']=claripy.BVS(f'spinmove_list_{delta}_{y}_{i}',8)
 assert_pathwise_equivalent(asm(v,delta,maxy,y),native(v,delta,maxy,y),(*REGISTERS,'state'))
