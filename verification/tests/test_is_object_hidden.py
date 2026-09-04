from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr, claripy, pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate, Sm83CpRegister, Sm83LoadAAtHlIncrement, Sm83LoadAHighImmediate, Sm83XorA

ROOT=Path(__file__).resolve().parents[2]; ELF=ROOT/'verification/build/ports.elf'; ROM=ROOT/'pokered.gbc'; SYMBOLS=ROOT/'pokered.sym'; NS=0x100000; NM=0x200000; STACK=0xd000; RET=0xffff
LIST=0xd5ce; FLAGS=0xd5a6; OFFSET=0xffda; HIDDEN=0xffe5

@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;state:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Reg(angr.SimProcedure):
 def __init__(self,d,s,n):super().__init__();self.d=d;self.s=s;self.n=n
 def run(self):setattr(self.state.regs,self.d,getattr(self.state.regs,self.s));self.jump(self.n) # type: ignore[override]
class Imm(angr.SimProcedure):
 def __init__(self,r,v,n):super().__init__();self.r=r;self.v=v;self.n=n
 def run(self):setattr(self.state.regs,self.r,claripy.BVV(self.v,8));self.jump(self.n) # type: ignore[override]
class HL(angr.SimProcedure):
 def __init__(self,v,n):super().__init__();self.v=v;self.n=n
 def run(self):self.state.regs.hl=claripy.BVV(self.v,16);self.jump(self.n) # type: ignore[override]
class SwapA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  a=self.state.regs.a;self.state.regs.a=claripy.Concat(a[3:0],a[7:4]);self.state.regs.f=claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8));self.jump(self.n) # type: ignore[override]
class Branch(angr.SimProcedure):
 def __init__(self,t,f,when_z):super().__init__();self.t=t;self.f=f;self.when_z=when_z
 def run(self):
  z=(self.state.regs.f&0x40)!=0
  if not self.when_z:z=~z
  t,f=self.state.copy(),self.state.copy();t.solver.add(z);f.solver.add(~z);t.regs.ip=claripy.BVV(self.t,16);f.regs.ip=claripy.BVV(self.f,16);self.inhibit_autoret=True;self.successors.add_successor(t,self.t,z,'Ijk_Boring');self.successors.add_successor(f,self.f,~z,'Ijk_Boring') # type: ignore[override]
class Call(angr.SimProcedure):
 def __init__(self,t,n):super().__init__();self.t=t;self.n=n
 def run(self):
  sp=self.state.regs.sp-2;self.state.memory.store(sp,claripy.BVV(self.n,16),endness='Iend_LE');self.state.regs.sp=sp;self.jump(self.t) # type: ignore[override]
class Toggle(angr.SimProcedure):
 def run(self):
  c=self.state.regs.c;addr=claripy.BVV(FLAGS,16)+(claripy.ZeroExt(8,c)>>3);v=self.state.memory.load(addr,1);mask=claripy.BVV(1,8)<<(c&7);a=v&mask;self.state.regs.a=a;self.state.regs.c=a;self.state.regs.f=claripy.BVV(0x10,8)|claripy.If(a==0,claripy.BVV(0x40,8),claripy.BVV(0,8));sp=self.state.regs.sp;target=self.state.memory.load(sp,2,endness='Iend_LE');self.state.regs.sp=sp+2;self.jump(target) # type: ignore[override]
class AndA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.f=claripy.BVV(0x10,8)|claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8));self.jump(self.n) # type: ignore[override]
class StoreHidden(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.memory.store(HIDDEN,self.state.regs.a);self.jump(self.n) # type: ignore[override]
class Return(angr.SimProcedure):
 def run(self):sp=self.state.regs.sp;target=self.state.memory.load(sp,2,endness='Iend_LE');self.state.regs.sp=sp+2;self.jump(target) # type: ignore[override]

def setup(s,base,v,entries,flag):
 s.memory.store(base+OFFSET,claripy.BVV(0x10,8))
 for i in range(3):s.memory.store(base+LIST+i,claripy.BVV(entries[i] if i<len(entries) else 0,8))
 s.memory.store(base+FLAGS,claripy.BVV(flag,8));s.memory.store(base+HIDDEN,claripy.BVV(0x55,8))
def endpoint(s,native):
 base=NM if native else 0; r=native_registers(s,NS) if native else assembly_registers(s)
 return E(**r,state=claripy.Concat(*(s.memory.load(base+a,1) for a in (LIST,LIST+1,LIST+2,FLAGS,HIDDEN,OFFSET))),constraints=tuple(s.solver.constraints))
def assembly(v,entries,flag):
 l=symbol_location(SYMBOLS,'IsObjectHidden');t=symbol_location(SYMBOLS,'ToggleableObjectFlagAction');assert linked_bytes(ROM,l,34).hex()=='f0dacb374721ced52afeff2811b82a20f74f060221a6d5cde67179a72001afe0e5c9'
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address
 p.hook(q,Sm83LoadAHighImmediate(0xda,q+2),length=2);p.hook(q+2,SwapA(q+4),length=2);p.hook(q+4,Reg('b','a',q+5),length=1);p.hook(q+5,HL(LIST,q+8),length=3);p.hook(q+8,Sm83LoadAAtHlIncrement(q+9),length=1);p.hook(q+9,Sm83CpImmediate(0xff,q+11),length=2);p.hook(q+11,Branch(q+30,q+13,True),length=2);p.hook(q+13,Sm83CpRegister('b',q+14),length=1);p.hook(q+14,Sm83LoadAAtHlIncrement(q+15),length=1);p.hook(q+15,Branch(q+8,q+17,False),length=2);p.hook(q+17,Reg('c','a',q+18),length=1);p.hook(q+18,Imm('b',2,q+20),length=2);p.hook(q+20,HL(FLAGS,q+23),length=3);p.hook(q+23,Call(t.address,q+26),length=3);p.hook(t.address,Toggle(),length=63);p.hook(q+26,Reg('a','c',q+27),length=1);p.hook(q+27,AndA(q+28),length=1);p.hook(q+28,Branch(q+31,q+30,False),length=2);p.hook(q+30,Sm83XorA(q+31),length=1);p.hook(q+31,StoreHidden(q+33),length=2);p.hook(q+33,Return(),length=1)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,v);setup(s,0,v,entries,flag);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RET,16),endness='Iend_LE');m=p.factory.simulation_manager(s);m.explore(find=RET,num_find=10);assert not m.errored and m.found;return [endpoint(x,False) for x in m.found]
def native(v,entries,flag):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_is_object_hidden');assert f;s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,NM,v,entries,flag);m=p.factory.simulation_manager(s);m.run();assert not m.errored and m.deadended;return [endpoint(x,True) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),reason='build artifacts missing')
@pytest.mark.parametrize(('entries','flag'),[((0xff,),0),((0x20,0x05,0xff),0),((0x01,0x00,0xff),0),((0x01,0x00,0xff),1)])
def test_is_object_hidden_pathwise_equivalence(entries,flag):
 v=symbolic_registers('is_hidden');assert_pathwise_equivalent(assembly(v,entries,flag),native(v,entries,flag),(*REGISTERS,'state'))
