from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr, claripy, pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import linked_bytes, rom_window, symbol_location

ROOT=Path(__file__).resolve().parents[2]; ELF=ROOT/'verification/build/ports.elf'; ROM=ROOT/'pokered.gbc'; SYMBOLS=ROOT/'pokered.sym'; NS=0x100000; NM=0x200000; RET=0xffff
WARPS,Y,X,DW,DM,MOVE,PAL=0xd3ae,0xd361,0xd362,0xd42f,0xff8b,0xd736,0xd35d
BGP,OBP0,OBP1=0xff47,0xff48,0xff49; FADE=0x2116
BODY=bytes.fromhex('0603215f43cdd635fa5dd3a7caf620c3ba20')

@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;state:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Load(angr.SimProcedure):
 def __init__(self,a,n):super().__init__();self.a=a;self.n=n
 def run(self):self.state.regs.a=self.state.memory.load(self.a,1);self.jump(self.n) # type: ignore[override]
class AndA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.f=claripy.BVV(0x10,8)|claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8));self.jump(self.n) # type: ignore[override]
class WarpNone(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.b=claripy.BVV(3,8);self.state.regs.h=claripy.BVV(0x43,8);self.state.regs.l=claripy.BVV(0x5f,8);self.state.regs.a=claripy.BVV(0,8);self.state.regs.f=claripy.BVV(0x50,8);self.jump(self.n) # type: ignore[override]
class Palette(angr.SimProcedure):
 def run(self):
  s=self.state; a=s.memory.load(FADE-1,1);s.memory.store(BGP,a);a=s.memory.load(FADE,1);s.memory.store(OBP0,a);a=s.memory.load(FADE+1,1);s.memory.store(OBP1,a);s.regs.a=a;s.regs.b=claripy.BVV(1,8);s.regs.h=claripy.BVV(0x21,8);s.regs.l=claripy.BVV(0x18,8);s.regs.f=claripy.BVV(2,8);self.jump(RET) # type: ignore[override]
def setup(s,b,i):
 for a,k in ((WARPS,'warps'),(Y,'y'),(X,'x'),(DW,'dw'),(DM,'dm'),(MOVE,'move')):s.memory.store(b+a,i[k])
 s.memory.store(b+PAL,claripy.BVV(1,8));s.memory.store(b+FADE-1,i['p0']);s.memory.store(b+FADE,i['p1']);s.memory.store(b+FADE+1,i['p2'])
def end(s,n):
 b=NM if n else 0;r=native_registers(s,NS) if n else assembly_registers(s);w=(WARPS,Y,X,DW,DM,MOVE,PAL,FADE-1,FADE,FADE+1,BGP,OBP0,OBP1);return E(**r,state=claripy.Concat(*(s.memory.load(b+a,1) for a in w)),constraints=tuple(s.solver.constraints))
def asm(i):
 l=symbol_location(SYMBOLS,'MapEntryAfterBattle');assert linked_bytes(ROM,l,len(BODY))==BODY;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q,WarpNone(q+8),length=8);p.hook(q+8,Load(PAL,q+11),length=3);p.hook(q+11,AndA(q+12),length=1);p.hook(q+12,Palette(),length=3);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i);setup(s,0,i);m=p.factory.simulation_manager(s);m.explore(find=RET);assert not m.errored and len(m.found)==1;return [end(m.found[0],False)]
def native(i):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_map_entry_after_battle');assert f;s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,i);setup(s,NM,i);m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1;return [end(m.deadended[0],True)]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),reason='artifacts')
def test_map_entry_after_battle_pathwise_equivalence():
 i=symbolic_registers('map_entry');
 for k in ('warps','y','x','dw','dm','move','p0','p1','p2'):i[k]=claripy.BVS('map_entry_'+k,8)
 i['warps']=claripy.BVV(0,8)
 assert_pathwise_equivalent(asm(i),native(i),(*REGISTERS,'state'))
