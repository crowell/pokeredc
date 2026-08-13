from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83DecRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xefff
class Store(angr.SimProcedure):
 def __init__(self,value,n):super().__init__();self.value=value;self.n=n
 def run(self):self.state.globals['written']=claripy.BVV(self.value,8);self.jump(self.n)  # type: ignore[override]
class Bound(angr.SimProcedure):
 def __init__(self,reg,result_mode=True):super().__init__();self.reg=reg;self.result_mode=result_mode
 def run(self):self.state.globals['result']=claripy.If(getattr(self.state.regs,self.reg)==0,claripy.BVV(1,8),claripy.BVV(0,8)) if self.result_mode else claripy.BVV(2,8);self.jump(DONE)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p);i['written']=claripy.BVS(p+'_written',8);return i
def asm_phase(i,phase):
 l=symbol_location(SYMBOLS,'DrawLineBox');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address
 if phase=='begin':start=q;p.hook(q+3,Bound('b',False),length=0)
 elif phase=='vertical':start=q+3;p.hook(q+3,Store(0x78,q+5),length=2);p.hook(q+5,Sm83AddHlRegisterPair('de',q+6),length=1);p.hook(q+6,Sm83DecRegister('b',q+7),length=1);p.hook(q+7,Bound('b'),length=2)
 elif phase=='corner':start=q+9;p.hook(q+9,Store(0x77,q+11),length=2);p.hook(q+12,Bound('c',False),length=0)
 elif phase=='horizontal':start=q+12;p.hook(q+12,Store(0x76,q+14),length=2);p.hook(q+15,Sm83DecRegister('c',q+16),length=1);p.hook(q+16,Bound('c'),length=2)
 else:start=q+18;p.hook(q+18,Store(0x6f,q+20),length=2)
 s=p.factory.blank_state(addr=start);set_assembly_registers(s,i);s.globals['written']=i['written'];s.globals['result']=claripy.BVV(2,8);s.regs.sp=0xd000;s.memory.store(0xd000,claripy.BVV(0xffff,16),endness='Iend_LE')
 if phase=='finish':
  from verification.harness.rom import collect_returns
  ends=collect_returns(p,s,0xffff)
 else:
  m=p.factory.simulation_manager(s);m.explore(find=DONE);ends=m.found
 return [E(**assembly_registers(x),memory=x.globals['written'],result=x.globals['result'],constraints=tuple(x.solver.constraints)) for x in ends]
def native(i,phase):
 name='port_draw_line_box_'+phase+('_step' if phase in ('vertical','horizontal') else '');p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i['written']);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,1),result=x.regs.rax[7:0] if phase in ('vertical','horizontal') else claripy.BVV(2,8),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('phase',('begin','vertical','corner','horizontal','finish'))
def test_phase(phase):
 i=inputs('line_'+phase);assert_pathwise_equivalent(asm_phase(i,phase),native(i,phase),(*REGISTERS,'memory','result'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'DrawLineBox');assert linked_bytes(ROM,l,21)==bytes.fromhex('1114003678190520fa36772b36762b0d20fa366fc9')
