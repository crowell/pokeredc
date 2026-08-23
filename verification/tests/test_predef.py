from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
from verification.harness.sm83_shims import Sm83LoadAHighImmediate,Sm83LoadAImmediate,Sm83StoreAHighImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x400000;STACK=0xD000;RETURN=0xFFFF
EXPECTED=bytes.fromhex('ea4eccf0b8ea12cff53e13e0b8ea0020cd497efab7d0e0b8ea0020118d3ed5e9f1e0b8ea0020c9')
W_PREDEF_ID=0xCC4E;W_PREDEF_HL=0xCC4F;W_PREDEF_DE=0xCC51;W_PREDEF_BC=0xCC53;W_PREDEF_PARENT=0xCF12;W_PREDEF_BANK=0xD0B7;H_BANK=0xFFB8;R_ROMB=0x2000
SAVED=(W_PREDEF_HL,W_PREDEF_HL+1,W_PREDEF_DE,W_PREDEF_DE+1,W_PREDEF_BC,W_PREDEF_BC+1)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;wid:claripy.ast.BV;saved:claripy.ast.BV;parent:claripy.ast.BV;bank:claripy.ast.BV;hb:claripy.ast.BV;rromb:claripy.ast.BV;ptr:claripy.ast.BV;tgt:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class PointerCall(angr.SimProcedure):
 def __init__(self,next_address:int)->None:
  super().__init__();self._next=next_address
 def run(self):
  r=assembly_registers(self.state);m=self.state.memory
  self.state.globals['ptr']=claripy.Concat(*(r[x] for x in REGISTERS),m.load(W_PREDEF_ID,1),self.state.globals['fetched_bank'],self.state.globals['fetched_lo'],self.state.globals['fetched_hi'])
  for x in REGISTERS:
   v=self.state.globals[f'p_out_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  for i,a in enumerate(SAVED):m.store(a,self.state.globals[f'p_out_saved_{i}'])
  m.store(W_PREDEF_BANK,self.state.globals['p_out_bank'])
  self.jump(self._next)
class TargetBoundary(angr.SimProcedure):
 def __init__(self,next_address:int)->None:
  super().__init__();self._next=next_address
 def run(self):
  r=self.state.regs;r.d=claripy.BVV(0x3E,8);r.e=claripy.BVV(0x8D,8)
  r.sp=r.sp-2;self.state.memory.store(r.sp,claripy.BVV(0x3E8D,16),endness='Iend_LE')
  rr=assembly_registers(self.state);self.state.globals['tgt']=claripy.Concat(*(rr[x] for x in REGISTERS))
  for x in REGISTERS:
   v=self.state.globals[f't_out_{x}'];setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
  r.sp=r.sp+2
  self.jump(self._next)
class NPointer(angr.SimProcedure):
 """x86 function hook with an explicit RET so the replaced body never runs."""
 def run(self):
  s=self.state.regs.rdi;mm=self.state.memory
  self.state.globals['ptr']=claripy.Concat(mm.load(s,8),mm.load(s+8,1),mm.load(s+16,1),mm.load(s+17,1),mm.load(s+18,1))
  mm.store(s,claripy.Concat(*(self.state.globals[f'p_out_{x}'] for x in REGISTERS)))
  mm.store(s+9,claripy.Concat(*(self.state.globals[f'p_out_saved_{i}'] for i in range(6))))
  mm.store(s+15,self.state.globals['p_out_bank'])
  ra=mm.load(self.state.regs.sp,8,endness='Iend_LE');self.state.regs.sp=self.state.regs.sp+8;self.jump(ra)
class NTarget(angr.SimProcedure):
 def run(self):
  s=self.state.regs.rdi
  self.state.globals['tgt']=self.state.memory.load(s,8)
  self.state.memory.store(s,claripy.Concat(*(self.state.globals[f't_out_{x}'] for x in REGISTERS)))
  ra=self.state.memory.load(self.state.regs.sp,8,endness='Iend_LE');self.state.regs.sp=self.state.regs.sp+8;self.jump(ra)
def inputs(p):
 v=symbolic_registers(p)
 for x in REGISTERS:v[f'p_out_{x}']=claripy.Concat(claripy.BVS(f'{p}_p_out_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(f'{p}_p_out_{x}',8)
 for i in range(6):v[f'p_out_saved_{i}']=claripy.BVS(f'{p}_p_out_saved_{i}',8)
 v['p_out_bank']=claripy.BVS(f'{p}_p_out_bank',8)
 for x in REGISTERS:v[f't_out_{x}']=claripy.Concat(claripy.BVS(f'{p}_t_out_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(f'{p}_t_out_{x}',8)
 v['fetched_bank']=claripy.BVS(f'{p}_fetched_bank',8);v['fetched_lo']=claripy.BVS(f'{p}_fetched_lo',8);v['fetched_hi']=claripy.BVS(f'{p}_fetched_hi',8)
 v['init_hbank']=claripy.BVS(f'{p}_init_hbank',8)
 return v
def setup(s,v):
 s.globals['ptr']=claripy.BVV(0,12*8);s.globals['tgt']=claripy.BVV(0,8*8)
 for key,val in v.items():
  if key.startswith(('p_out_','t_out_','fetched_')):s.globals[key]=val
def assembly(v):
 l=symbol_location(SYMS,'Predef');assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+0,Sm83StoreAImmediate(W_PREDEF_ID,b+3),length=3)
 p.hook(b+3,Sm83LoadAHighImmediate(0xB8,b+5),length=2)
 p.hook(b+5,Sm83StoreAImmediate(W_PREDEF_PARENT,b+8),length=3)
 p.hook(b+11,Sm83StoreAHighImmediate(0xB8,b+13),length=2)
 p.hook(b+13,Sm83StoreAImmediate(R_ROMB,b+16),length=3)
 p.hook(b+16,PointerCall(b+19),length=3)
 p.hook(b+19,Sm83LoadAImmediate(W_PREDEF_BANK,b+22),length=3)
 p.hook(b+22,Sm83StoreAHighImmediate(0xB8,b+24),length=2)
 p.hook(b+24,Sm83StoreAImmediate(R_ROMB,b+27),length=3)
 p.hook(b+27,TargetBoundary(b+32),length=7)
 p.hook(b+33,Sm83StoreAHighImmediate(0xB8,b+35),length=2)
 p.hook(b+35,Sm83StoreAImmediate(R_ROMB,b+38),length=3)
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v);s.memory.store(H_BANK,v['init_hbank']);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(s);m.explore(find=lambda st:st.addr==RETURN,num_find=8);assert not m.errored and len(m.found)==1
 return [E(**assembly_registers(x),wid=x.memory.load(W_PREDEF_ID,1),saved=claripy.Concat(*(x.memory.load(a,1) for a in SAVED)),parent=x.memory.load(W_PREDEF_PARENT,1),bank=x.memory.load(W_PREDEF_BANK,1),hb=x.memory.load(H_BANK,1),rromb=x.memory.load(R_ROMB,1),ptr=x.globals['ptr'],tgt=x.globals['tgt'],constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_predef');pp=p.loader.find_symbol('port_get_predef_pointer');tb=p.loader.find_symbol('port_predef_target_boundary');assert f and pp and tb
 p.hook(pp.rebased_addr,NPointer());p.hook(tb.rebased_addr,NTarget())
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v)
 s.memory.store(NM+H_BANK,v['init_hbank'])
 s.memory.store(NS+8,v['fetched_bank']);s.memory.store(NS+9,v['fetched_lo']);s.memory.store(NS+10,v['fetched_hi'])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1
 return [E(**native_registers(x,NS),wid=x.memory.load(NM+W_PREDEF_ID,1),saved=claripy.Concat(*(x.memory.load(NM+a,1) for a in SAVED)),parent=x.memory.load(NM+W_PREDEF_PARENT,1),bank=x.memory.load(NM+W_PREDEF_BANK,1),hb=x.memory.load(NM+H_BANK,1),rromb=x.memory.load(NM+R_ROMB,1),ptr=x.globals['ptr'],tgt=x.globals['tgt'],constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_predef_pathwise_equivalence():
 v=inputs('predef');assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'wid','saved','parent','bank','hb','rromb','ptr','tgt'))
