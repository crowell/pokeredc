from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83DecRegister,Sm83IncRegister,Sm83StoreAAtHlIncrement
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;STACK=0xd000;RETURN=0xffff
TILEMAP=0xc3a0;AREA=360
EXPECTED=bytes.fromhex('0168010421a0c33e7f220d20fc0520f9c3d73d')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;hl:claripy.ast.BV
 tilemap:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 v=symbolic_registers(p);v['tilemap_in']=claripy.BVS(f'{p}_tilemap_in',8*AREA)
 return v
def setup(s,v,native:bool):
 o=NM if native else 0
 s.memory.store(o+TILEMAP,v['tilemap_in'])
class Delay3Site(angr.SimProcedure):
 """Proven Delay3 composition boundary at the tail JP: three proved
 DelayFrame iterations leave A := 0, F := $50 in the raw assembly flag
 byte, and C := 0, with B/D/E/H/L preserved; the callee's RET pops the
 caller's sentinel."""
 def __init__(self,next_address:int)->None:
  super().__init__();self._next=next_address
 def run(self):
  self.state.regs.a=claripy.BVV(0,8);self.state.regs.f=claripy.BVV(0x42,8);self.state.regs.c=claripy.BVV(0,8)
  self.jump(self._next)
def assembly(v):
 l=symbol_location(SYMS,'ClearScreen');d=symbol_location(SYMS,'Delay3')
 assert l.bank==0 and d.bank==0
 assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 assert d.address==0x3dd7
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+3,Sm83IncRegister('b',b+4),length=1)                 # inc b
 p.hook(b+9,Sm83StoreAAtHlIncrement(b+10),length=1)            # ld [hli],a
 p.hook(b+10,Sm83DecRegister('c',b+11),length=1)               # dec c
 p.hook(b+13,Sm83DecRegister('b',b+14),length=1)               # dec b
 p.hook(b+16,Delay3Site(RETURN),length=3)                      # jp Delay3
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v,False);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(s);m.explore(find=lambda st:st.addr==RETURN,num_find=64);assert not m.errored and len(m.found)==1
 out=[]
 for x in m.found:
  ar=assembly_registers(x)
  out.append(E(**{**{k:v for k,v in ar.items() if k not in ('h','l')},'hl':x.regs.hl},tilemap=claripy.Concat(*(x.memory.load(TILEMAP+i,1) for i in range(AREA))),constraints=tuple(x.solver.constraints)))
 return out
def native(v):
 p=angr.Project(ELF,auto_load_libs=False)
 f=p.loader.find_symbol('port_clear_screen');assert f
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v,True)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1
 out=[]
 for x in m.deadended:
  nr=native_registers(x,NS)
  out.append(E(**{**{k:v for k,v in nr.items() if k not in ('h','l')},'hl':claripy.Concat(nr['h'],nr['l'])},tilemap=claripy.Concat(*(x.memory.load(NM+TILEMAP+i,1) for i in range(AREA))),constraints=tuple(x.solver.constraints)))
 return out
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_clear_screen_pathwise_equivalence():
 v=inputs('clear_screen');assert_pathwise_equivalent(assembly(v),native(v),('a','f','b','c','d','e','hl','tilemap'))
