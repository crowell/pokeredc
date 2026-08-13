from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location,sm83_flags_to_z80,z80_flags_to_sm83
from verification.harness.sm83_shims import Sm83CpAtHl,Sm83CpImmediate,Sm83AddHlRegisterPair
ROOT=Path(__file__).resolve().parents[2];ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';ELF=ROOT/'verification/build/ports.elf';NATIVE=0x100000;DONE=0xeff1
NAMES=('cur_species','mon_h_index','name_list_index','which_pokemon','candidate_char','standard_char','saved_a','saved_f','loaded_rom_bank','get_name_called','copy_called','copy_source_h','copy_source_l','copy_destination_h','copy_destination_l')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Read(angr.SimProcedure):
 def __init__(self,key,n,inc=False):super().__init__();self.key=key;self.n=n;self.inc=inc
 def run(self):self.state.regs.a=self.state.globals[self.key];self.state.regs.de=self.state.regs.de+(1 if self.inc else 0);self.jump(self.n)
class Write(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.jump(self.n)
class PushAF(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['saved_a']=self.state.regs.a;self.state.globals['saved_f']=z80_flags_to_sm83(self.state.regs.f);self.jump(self.n)
class PopAF(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=self.state.globals['saved_a'];self.state.regs.f=sm83_flags_to_z80(self.state.globals['saved_f']);self.jump(self.n)
class GetName(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['get_name_called']=claripy.BVV(1,8);self.jump(self.n)
class Compare(angr.SimProcedure):
 def run(self):
  left=self.state.regs.a;right=self.state.globals['standard_char'];f=claripy.BVV(2,8)|claripy.If(left==right,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If((left&15).ULT(right&15),claripy.BVV(0x10,8),claripy.BVV(0,8))|claripy.If(left.ULT(right),claripy.BVV(1,8),claripy.BVV(0,8));self.state.regs.f=f;self.state.regs.hl=self.state.regs.hl+1;self.inhibit_autoret=True;z=(f&0x40)!=0;self.successors.add_successor(self.state.copy(),0x6f13,z,'Ijk_Boring');self.successors.add_successor(self.state.copy(),DONE,claripy.Not(z),'Ijk_Boring')
class CompareLoopBranch(angr.SimProcedure):
 def run(self):
  self.inhibit_autoret=True;z=(self.state.regs.f&0x40)!=0;self.state.globals['continuation']=claripy.If(z,claripy.BVV(2,8),claripy.BVV(1,8));self.successors.add_successor(self.state,DONE,claripy.BoolV(True),'Ijk_Boring')
class CopyBoundary(angr.SimProcedure):
 def run(self):
  self.state.globals['copy_called']=claripy.BVV(1,8);self.state.globals['copy_source_h']=self.state.regs.h;self.state.globals['copy_source_l']=self.state.regs.l;self.state.globals['copy_destination_h']=self.state.regs.d;self.state.globals['copy_destination_l']=self.state.regs.e;self.jump(DONE)
class PushNickname(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['copy_destination_h']=self.state.regs.h;self.state.globals['copy_destination_l']=self.state.regs.l;self.jump(self.n)
class PopNickname(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.d=self.state.globals['copy_destination_h'];self.state.regs.e=self.state.globals['copy_destination_l'];self.jump(self.n)
class AddNicknameOffset(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  count=self.state.regs.a;self.state.regs.hl=self.state.regs.hl+claripy.ZeroExt(8,count)*11;self.state.regs.a=0;self.jump(self.n)
class GetNewName(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  species=self.state.globals['cur_species'];right=claripy.BVV(0xc4,8);f=claripy.BVV(2,8)|claripy.If(species==right,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If((species&15).ULT(right&15),claripy.BVV(0x10,8),claripy.BVV(0,8))|claripy.If(species.ULT(right),claripy.BVV(1,8),claripy.BVV(0,8));self.state.regs.a=self.state.globals['loaded_rom_bank'];self.state.regs.f=f;self.state.globals['get_name_called']=claripy.BVV(1,8);self.jump(self.n)
class Continuation(angr.SimProcedure):
 def __init__(self,c):super().__init__();self.c=c
 def run(self):self.state.globals['continuation']=claripy.BVV(self.c,8);self.jump(DONE)
class SetPointers(angr.SimProcedure):
 def run(self):self.state.regs.hl=0xcd6d;self.state.regs.de=0xcf11;self.jump(DONE)
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=(claripy.Concat(claripy.BVS(p+'_'+n,4),claripy.BVV(0,4)) if n=='saved_f' else claripy.BVS(p+'_'+n,8))
 return i
def project():
 l=symbol_location(SYMBOLS,'RenameEvolvedMon');return angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address}),l.address
def setup(s,i):set_assembly_registers(s,i);[s.globals.__setitem__(n,i[n]) for n in NAMES]
def ep(x):return E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[n] for n in NAMES)),continuation=x.globals.get('continuation',claripy.BVV(0,8)),constraints=tuple(x.solver.constraints))
def collect(m):
 m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr==DONE)
  if m.active:m.step()
 return [ep(x) for x in m.found]
def assembly_begin(i):
 p,q=project();p.hook(q,Read('cur_species',q+3),length=3);p.hook(q+3,PushAF(q+4),length=1);p.hook(q+4,Read('mon_h_index',q+7),length=3);p.hook(q+7,Write('name_list_index',q+10),length=3);p.hook(q+10,GetName(DONE),length=3);s=p.factory.blank_state(addr=q);setup(s,i);return collect(p.factory.simulation_manager(s))
def assembly_after(i):
 p,q=project();p.hook(q+13,PopAF(q+14),length=1);p.hook(q+14,Write('cur_species',q+17),length=3);p.hook(q+17,SetPointers(),length=6);s=p.factory.blank_state(addr=q+13);setup(s,i);return collect(p.factory.simulation_manager(s))
def assembly_compare(i):
 p,q=project();p.hook(q+23,Read('candidate_char',q+24,True),length=1);p.hook(q+24,Compare(),length=2);p.hook(q+28,Sm83CpImmediate(0x50,q+30),length=2);p.hook(q+30,CompareLoopBranch(),length=2);s=p.factory.blank_state(addr=q+23);setup(s,i);return collect(p.factory.simulation_manager(s))
def assembly_copy(i):
 p,q=project();p.hook(q+32,Read('which_pokemon',q+35),length=3);p.hook(q+41,AddNicknameOffset(q+44),length=3);p.hook(q+44,PushNickname(q+45),length=1);p.hook(q+45,GetNewName(q+48),length=3);p.hook(q+51,PopNickname(q+52),length=1);p.hook(q+52,CopyBoundary(),length=3);s=p.factory.blank_state(addr=q+32);setup(s,i);return collect(p.factory.simulation_manager(s))
def native(name,i,returns=False):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol(name);s=p.factory.call_state(f.rebased_addr,NATIVE);store_native_registers(s,NATIVE,i);s.memory.store(NATIVE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();return [E(**native_registers(x,NATIVE),memory=x.memory.load(NATIVE+8,len(NAMES)),continuation=(x.regs.rax[7:0] if returns else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.parametrize('assembly,name,returns',((assembly_begin,'port_rename_evolved_mon_begin',False),(assembly_after,'port_rename_evolved_mon_after_get_name',False),(assembly_compare,'port_rename_evolved_mon_compare_step',True),(assembly_copy,'port_rename_evolved_mon_copy_begin',False)))
def test_equivalence(assembly,name,returns):
 i=inputs(name);assert_pathwise_equivalent(assembly(i),native(name,i,returns),(*REGISTERS,'memory','continuation'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'RenameEvolvedMon');assert linked_bytes(ROM,l,55)==bytes.fromhex('fab5d0f5fab8d0eab5d0cd6b37f1eab5d0216dcd114bcf1a13be23c0fe5020f7fa92cf010b0021b5d2cd873ae5cd6b37216dcdd1c3b500')
