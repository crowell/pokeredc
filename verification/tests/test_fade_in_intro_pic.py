from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83DecRegister,Sm83LoadAAtHlIncrement,Sm83StoreAHighImmediate
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;STACK=0xd000;RETURN=0xffff
TABLE=0x6282;RBGP=0xff47;VBL=0xffd6
EXPECTED=bytes.fromhex('21826206062ae0470e0acd39370520f5c9')
PALETTES=bytes.fromhex('54a8fcf8f4e4')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
 bgp:claripy.ast.BV;vbl:claripy.ast.BV;frames:claripy.ast.BV
 constraints:tuple[claripy.ast.Bool,...]
class DelayFramesBoundary(angr.SimProcedure):
 """Proven DelayFrames terminal transition: A := 0, C := 0, F := Z|N while
 preserving B/DE/HL; the iteration count is the incoming C (10 here)."""
 def run(self):
  self.state.globals['frames']=self.state.regs.c
  self.state.regs.a=claripy.BVV(0,8);self.state.regs.c=claripy.BVV(0,8)
  self.state.regs.f=claripy.BVV(0x42,8)
  ret=self.state.memory.load(self.state.regs.sp,2,endness='Iend_LE')
  self.state.regs.sp=self.state.regs.sp+2
  self.jump(ret)
class NDelayFrames(angr.SimProcedure):
 def run(self,s,m):
  self.state.globals['frames']=self.state.memory.load(s+3,1)
  self.state.memory.store(s,claripy.BVV(0,8))
  self.state.memory.store(s+3,claripy.BVV(0,8))
  self.state.memory.store(s+1,claripy.BVV(0xc0,8))
def inputs(p):
 v=symbolic_registers(p)
 v['bgp']=claripy.BVS(p+'_bgp',8);v['vbl']=claripy.BVS(p+'_vbl',8)
 return v
def setup(s,v,native:bool):
 o=NM if native else 0
 s.memory.store(o+RBGP,v['bgp']);s.memory.store(o+VBL,v['vbl'])
 s.globals['frames']=None
def assembly(v):
 l=symbol_location(SYMS,'FadeInIntroPic');df=symbol_location(SYMS,'DelayFrames')
 assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 assert linked_bytes(ROM,symbol_location(SYMS,'IntroFadePalettes'),6)==PALETTES
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+5,Sm83LoadAAtHlIncrement(b+6),length=1)          # ld a,[hli]
 p.hook(b+6,Sm83StoreAHighImmediate(0x47,b+8),length=2)    # ldh [rBGP],a
 p.hook(b+13,Sm83DecRegister('b',b+14),length=1)           # dec b
 p.hook(df.address,DelayFramesBoundary())                  # call DelayFrames
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v,False);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(s);m.explore(find=lambda st:st.addr==RETURN,num_find=64);assert not m.errored and len(m.found)==1
 return [E(**assembly_registers(x),bgp=x.memory.load(RBGP,1),vbl=x.memory.load(VBL,1),frames=x.globals['frames'],constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False)
 df=p.loader.find_symbol('port_delay_frames');assert df is not None
 p.hook(df.rebased_addr,NDelayFrames())
 f=p.loader.find_symbol('port_fade_in_intro_pic');assert f
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v,True)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1
 return [E(**native_registers(x,NS),bgp=x.memory.load(NM+RBGP,1),vbl=x.memory.load(NM+VBL,1),frames=x.globals['frames'],constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_fade_in_intro_pic_pathwise_equivalence():
 v=inputs('fade_in_intro_pic');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'bgp','vbl','frames'))
