from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
from verification.harness.sm83_shims import Sm83AddImmediate,Sm83CpImmediate,Sm83DecRegister,Sm83IncRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;NATIVE_CALLBACK=0x100100;NATIVE_GLOBALS=0x100200;DONE=0xefff;KEYS=('current_offset','movement_byte','movement_delay','movement_status','animation_frame','dispatched')
class Read(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)  # type: ignore[override]
class StoreImmediate(angr.SimProcedure):
 def __init__(self,key,value,n):super().__init__();self.key=key;self.value=value;self.n=n
 def run(self):self.state.globals[self.key]=claripy.BVV(self.value,8);self.jump(self.n)  # type: ignore[override]
class DecDelay(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  old=self.state.globals['movement_delay'];new=old-1;flags=self.state.regs.f&1;flags|=claripy.BVV(2,8);flags|=claripy.If(new==0,claripy.BVV(0x40,8),claripy.BVV(0,8));flags|=claripy.If((old&0xf)==0,claripy.BVV(0x10,8),claripy.BVV(0,8));self.state.globals['movement_delay']=new;self.state.regs.f=flags;self.jump(self.n)  # type: ignore[override]
class Boundary(angr.SimProcedure):
 def __init__(self,full):super().__init__();self.full=full
 def run(self):
  self.state.globals['dispatched']=claripy.BVV(1,8)
  if self.full:
   cb=self.state.globals['callback']
   for r in REGISTERS:setattr(self.state.regs,r,sm83_flags_to_z80(cb[r]) if r=='f' else cb[r])
   for k in KEYS[:5]:self.state.globals[k]=cb[k]
  self.jump(DONE)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for k in KEYS:i[k]=claripy.BVS(f'{p}_{k}',8)
 for r,v in symbolic_registers(p+'_callback').items():i['callback_'+r]=v
 for k in KEYS[:5]:i['callback_'+k]=claripy.BVS(f'{p}_callback_{k}',8)
 return i
def assembly(i,full):
 l=symbol_location(SYMBOLS,'UpdateSpriteMovementDelay');target=symbol_location(SYMBOLS,'UpdateSpriteImage').address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q+2,Read('current_offset',q+4),length=2);p.hook(q+4,Sm83AddImmediate(6,q+6),length=2);p.hook(q+7,Read('movement_byte',q+8),length=1);p.hook(q+10,Sm83CpImmediate(0xfe,q+12),length=2);p.hook(q+14,StoreImmediate('movement_delay',0,q+16),length=2);p.hook(q+18,DecDelay(q+19),length=1);p.hook(q+21,Sm83DecRegister('h',q+22),length=1);p.hook(q+22,Read('current_offset',q+24),length=2);p.hook(q+24,Sm83IncRegister('a',q+25),length=1);p.hook(q+26,StoreImmediate('movement_status',1,q+28),length=2);p.hook(q+30,Read('current_offset',q+32),length=2);p.hook(q+32,Sm83AddImmediate(8,q+34),length=2);p.hook(q+35,StoreImmediate('animation_frame',0,q+37),length=2);p.hook(target,Boundary(full));s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for k in KEYS:s.globals[k]=i[k]
 s.globals['dispatched']=claripy.BVV(0,8);s.globals['callback']={r:i['callback_'+r] for r in REGISTERS}|{k:i['callback_'+k] for k in KEYS[:5]};m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=10);return [E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[k] for k in KEYS)),constraints=tuple(x.solver.constraints)) for x in m.found]
def native(i,full):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);name='port_update_sprite_movement_delay' if full else 'port_update_sprite_movement_delay_begin';fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE,NATIVE_CALLBACK,NATIVE_GLOBALS) if full else p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[k] for k in KEYS)))
 if full:store_native_registers(s,NATIVE_CALLBACK,{r:i['callback_'+r] for r in REGISTERS});s.memory.store(NATIVE_GLOBALS,claripy.Concat(*(i['callback_'+k] for k in KEYS[:5])))
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(KEYS)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('full',(False,True))
def test_equivalence(full):
 i=inputs('sprite_delay_'+str(full));assert_pathwise_equivalent(assembly(i,full),native(i,full),(*REGISTERS,'memory'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'UpdateSpriteMovementDelay');assert linked_bytes(ROM,l,40)==bytes.fromhex('26c2f0dac6066f7e2c2cfefe30043600180335200725f0da3c6f360126c1f0dac6086f3600c35751')
