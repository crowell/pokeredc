from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location,z80_flags_to_sm83,sm83_flags_to_z80
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83DecRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xefff;KEYS=('sprite_offset','sprite_width','sprite_height','fetched','written','saved_a','saved_f','saved_h','saved_l')
class Read(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)  # type: ignore[override]
class Fetch(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=self.state.globals['fetched'];self.jump(self.n)  # type: ignore[override]
class WriteHli(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['written']=self.state.regs.a;self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
class SaveAfHl(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['saved_a']=self.state.regs.a;self.state.globals['saved_f']=z80_flags_to_sm83(self.state.regs.f);self.state.globals['saved_h']=self.state.regs.h;self.state.globals['saved_l']=self.state.regs.l;self.jump(self.n)  # type: ignore[override]
class RestoreHl(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.h=self.state.globals['saved_h'];self.state.regs.l=self.state.globals['saved_l'];self.jump(self.n)  # type: ignore[override]
class RestoreAf(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=self.state.globals['saved_a'];self.state.regs.f=sm83_flags_to_z80(self.state.globals['saved_f']);self.jump(self.n)  # type: ignore[override]
class Bound(angr.SimProcedure):
 def __init__(self,reg=None):super().__init__();self.reg=reg
 def run(self):self.state.globals['result']=claripy.If(getattr(self.state.regs,self.reg)==0,claripy.BVV(1,8),claripy.BVV(0,8)) if self.reg else claripy.BVV(2,8);self.jump(DONE)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.Concat(claripy.BVS(f'{p}_{k}',4),claripy.BVV(0,4)) if k=='saved_f' else claripy.BVS(f'{p}_{k}',8)
 return i
def assembly(i,phase):
 l=symbol_location(SYMBOLS,'AlignSpriteDataCentered');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address
 if phase=='begin':start=q;p.hook(q,Read('sprite_offset',q+2),length=2);p.hook(q+5,Sm83AddHlRegisterPair('bc',q+6),length=1);p.hook(q+6,Read('sprite_width',q+8),length=2);p.hook(q+8,Bound(),length=0)
 elif phase=='column_begin':start=q+8;p.hook(q+8,SaveAfHl(q+10),length=2);p.hook(q+10,Read('sprite_height',q+12),length=2);p.hook(q+13,Bound(),length=0)
 elif phase=='inner_step':start=q+13;p.hook(q+13,Fetch(q+14),length=1);p.hook(q+15,WriteHli(q+16),length=1);p.hook(q+16,Sm83DecRegister('c',q+17),length=1);p.hook(q+17,Bound('c'),length=2)
 else:start=q+19;p.hook(q+19,RestoreHl(q+20),length=1);p.hook(q+23,Sm83AddHlRegisterPair('bc',q+24),length=1);p.hook(q+24,RestoreAf(q+25),length=1);p.hook(q+25,Sm83DecRegister('a',q+26),length=1);p.hook(q+26,Bound('a'),length=2)
 s=p.factory.blank_state(addr=start);set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
 s.globals['result']=claripy.BVV(2,8);m=p.factory.simulation_manager(s);m.explore(find=DONE);return [E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[k] for k in KEYS)),result=x.globals['result'],constraints=tuple(x.solver.constraints)) for x in m.found]
def native(i,phase):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_align_sprite_data_centered_'+phase);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),result=x.regs.rax[7:0] if phase.endswith('step') or phase.endswith('finish') else claripy.BVV(2,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('phase',('begin','column_begin','inner_step','column_finish'))
def test_phase(phase):
 i=inputs('align_'+phase);assert_pathwise_equivalent(assembly(i,phase),native(i,phase),(*REGISTERS,'memory','result'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'AlignSpriteDataCentered');assert linked_bytes(ROM,l,29)==bytes.fromhex('f08d06004f09f08bf5e5f08c4f1a13220d20fae101380009f13d20ecc9')
