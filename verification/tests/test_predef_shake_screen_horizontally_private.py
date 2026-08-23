from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000
FIELDS=tuple(f'predef{i}' for i in range(6))+('mutate_wx','wx')
MUTATE=bytes.fromhex('f097a8e097cb7f2801afc607e04b0e04c33937')
STEP=bytes.fromhex('e097cd3f410e01cd3937cd3f41057820ef')
BODY=bytes.fromhex('cd943eafe097cd3f410e01cd3937cd3f41057820ef3e07e04bc9')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;state:claripy.ast.BV;calls:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def out(p,n,r):
 return claripy.Concat(claripy.BVS(f'{p}_{n}_flags',4),claripy.BVV(0,4)) if r=='f' else claripy.BVS(f'{p}_{n}_{r}',8)
def inputs(p):
 v=symbolic_registers(p)
 for x in FIELDS:v[x]=claripy.BVS(f'{p}_{x}',8)
 for n in ('delay','predef','loop','mutate0','mutate1'):
  for r in REGISTERS:v[f'{n}_{r}']=out(p,n,r)
 for n in ('loop','mutate0','mutate1'):
  v[f'{n}_mutate_wx']=claripy.BVS(f'{p}_{n}_mutate_wx',8);v[f'{n}_wx']=claripy.BVS(f'{p}_{n}_wx',8)
 return v
def asm(v,symbol):
 l=symbol_location(SYMS,symbol);p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});s=p.factory.blank_state(addr=l.address);set_assembly_registers(s,v)
 for x in FIELDS:s.globals[x]=v[x]
 return l,s
def regs(s):
 x=assembly_registers(s);return [x[r] for r in REGISTERS]
def setregs(s,v,n,b0=False):
 for r in REGISTERS:
  x=claripy.BVV(0,8) if b0 and r=='b' else v[f'{n}_{r}'];setattr(s.regs,r,sm83_flags_to_z80(x) if r=='f' else x)
def ep(s,calls,cont):return E(**assembly_registers(s),state=claripy.Concat(*(s.globals[x] for x in FIELDS)),calls=calls,continuation=claripy.BVV(cont,8),constraints=tuple(s.solver.constraints))
class Delay(angr.SimProcedure):
 def run(self,p,o):
  i=self.state.globals.get('di',0);self.state.globals[f'dc{i}']=claripy.Concat(self.state.memory.load(p,10),self.state.memory.load(o,1));self.state.memory.store(p,claripy.Concat(*(self.state.globals[f'delay_{r}'] for r in REGISTERS)));self.state.globals['di']=i+1
class Mutate(angr.SimProcedure):
 def run(self,p):
  i=self.state.globals['mi'];self.state.globals[f'mc{i}']=claripy.Concat(self.state.memory.load(p,8),self.state.memory.load(p+14,2));self.state.memory.store(p,claripy.Concat(*(self.state.globals[f'mutate{i}_{r}'] for r in REGISTERS)));self.state.memory.store(p+14,claripy.Concat(self.state.globals[f'mutate{i}_mutate_wx'],self.state.globals[f'mutate{i}_wx']));self.state.globals['mi']=i+1
class Predef(angr.SimProcedure):
 def run(self,p):self.state.globals['pc']=self.state.memory.load(p,14);self.state.memory.store(p,claripy.Concat(*(self.state.globals[f'predef_{r}'] for r in REGISTERS)))
class Loop(angr.SimProcedure):
 def run(self,p):
  self.state.globals['lc']=claripy.Concat(self.state.memory.load(p,8),self.state.memory.load(p+14,2));self.state.memory.store(p,claripy.Concat(*(claripy.BVV(0,8) if r=='b' else self.state.globals[f'loop_{r}'] for r in REGISTERS)));self.state.memory.store(p+14,claripy.Concat(self.state.globals['loop_mutate_wx'],self.state.globals['loop_wx']))
def setup(s,v):
 store_native_registers(s,NS,v)
 for i,x in enumerate(FIELDS,8):s.memory.store(NS+i,v[x])
 for k,x in v.items():
  if k not in REGISTERS and k not in FIELDS:s.globals[k]=x
 s.globals['di']=0;s.globals['mi']=0
def nep(s,calls,cont):return E(**native_registers(s,NS),state=s.memory.load(NS+8,len(FIELDS)),calls=calls,continuation=cont,constraints=tuple(s.solver.constraints))
def mutate_asm(v):
 l,s=asm(v,'PredefShakeScreenHorizontally.MutateWX');assert linked_bytes(ROM,l,len(MUTATE))==MUTATE;x=s.globals['mutate_wx']^s.regs.b;s.globals['mutate_wx']=x;base=claripy.If((x&0x80)!=0,claripy.BVV(0,8),x);wide=claripy.ZeroExt(1,base)+7;res=wide[7:0];f=claripy.If(res==0,claripy.BVV(0x40,8),claripy.BVV(0,8));f|=claripy.If((base&15)+7>15,claripy.BVV(0x10,8),claripy.BVV(0,8));f|=claripy.ZeroExt(7,wide[8]);s.regs.a=res;s.regs.f=f;s.regs.c=claripy.BVV(4,8);s.globals['wx']=res;call=claripy.Concat(*regs(s),claripy.BVV(0,24));setregs(s,v,'delay');return [ep(s,call,0)]
def mutate_native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_predef_shake_screen_horizontally_mutate_wx');d=p.loader.find_symbol('port_delay_frames');assert f and d;p.hook(d.rebased_addr,Delay());s=p.factory.call_state(f.rebased_addr,NS);setup(s,v);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [nep(x,x.globals['dc0'],claripy.BVV(0,8)) for x in m.deadended]
def step_asm(v):
 l,s=asm(v,'PredefShakeScreenHorizontally.loop');assert linked_bytes(ROM,l,len(STEP))==STEP;s.globals['mutate_wx']=s.regs.a;calls=[]
 for i in range(2):
  calls.append(claripy.Concat(*regs(s),s.globals['mutate_wx'],s.globals['wx']));setregs(s,v,f'mutate{i}');s.globals['mutate_wx']=v[f'mutate{i}_mutate_wx'];s.globals['wx']=v[f'mutate{i}_wx']
  if i==0:s.regs.c=claripy.BVV(1,8);calls.append(claripy.Concat(*regs(s),claripy.BVV(0,24)));setregs(s,v,'delay')
 before=s.regs.b;res=before-1;f=(s.regs.f&1)|2;f|=claripy.If(res==0,claripy.BVV(0x40,8),claripy.BVV(0,8));f|=claripy.If((before&15)==0,claripy.BVV(0x10,8),claripy.BVV(0,8));s.regs.a=res;s.regs.b=res;s.regs.f=f;yes=s.copy();yes.add_constraints(res!=0);no=s.copy();no.add_constraints(res==0);cv=claripy.Concat(*calls);return [ep(yes,cv,1),ep(no,cv,0)]
def step_native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_predef_shake_screen_horizontally_step');u=p.loader.find_symbol('port_predef_shake_screen_horizontally_mutate_wx');d=p.loader.find_symbol('port_delay_frames');assert f and u and d;p.hook(u.rebased_addr,Mutate());p.hook(d.rebased_addr,Delay());s=p.factory.call_state(f.rebased_addr,NS);setup(s,v);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [nep(x,claripy.Concat(x.globals['mc0'],x.globals['dc0'],x.globals['mc1']),x.regs.rax[7:0]) for x in m.deadended]
def function_asm(v):
 l,s=asm(v,'PredefShakeScreenHorizontally');assert linked_bytes(ROM,l,len(BODY))==BODY;pc=claripy.Concat(*regs(s),*(s.globals[x] for x in FIELDS[:6]));setregs(s,v,'predef');s.regs.a=claripy.BVV(0,8);s.regs.f=claripy.BVV(0x40,8);lc=claripy.Concat(*regs(s),s.globals['mutate_wx'],s.globals['wx']);setregs(s,v,'loop',True);s.globals['mutate_wx']=v['loop_mutate_wx'];s.globals['wx']=claripy.BVV(7,8);s.regs.a=claripy.BVV(7,8);return [ep(s,claripy.Concat(pc,lc),0)]
def function_native(v):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_predef_shake_screen_horizontally_private');g=p.loader.find_symbol('port_get_predef_registers');l=p.loader.find_symbol('port_predef_shake_screen_horizontally_loop');assert f and g and l;p.hook(g.rebased_addr,Predef());p.hook(l.rebased_addr,Loop());s=p.factory.call_state(f.rebased_addr,NS);setup(s,v);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [nep(x,claripy.Concat(x.globals['pc'],x.globals['lc']),claripy.BVV(0,8)) for x in m.deadended]
FIELDS_EQ=(*REGISTERS,'state','calls','continuation')
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_predef_shake_screen_horizontally_mutate_wx_pathwise_equivalence():
 v=inputs('horizontal_mutate');assert_pathwise_equivalent(mutate_asm(v),mutate_native(v),FIELDS_EQ)
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_predef_shake_screen_horizontally_step_pathwise_equivalence():
 v=inputs('horizontal_step');assert_pathwise_equivalent(step_asm(v),step_native(v),FIELDS_EQ)
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_predef_shake_screen_horizontally_pathwise_equivalence():
 v=inputs('horizontal_function');assert_pathwise_equivalent(function_asm(v),function_native(v),FIELDS_EQ)
