from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location,z80_flags_to_sm83,sm83_flags_to_z80
from verification.harness.sm83_shims import Sm83AdcRegister,Sm83AddHlRegisterPair,Sm83AddRegister,Sm83AndImmediate,Sm83CpImmediate,Sm83CpRegister,Sm83DecRegister,Sm83IncRegister,Sm83SbcRegister,Sm83SubRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000;DONE=0xeff1
NAMES=('tile_animations','evolution_occurred','which_pokemon','party_species','evo_old_species','can_evolve','link_state','force_evolution','loaded_mon_level','evolution_type','requirement','level_requirement','cur_item','is_in_battle','music_called','cur_enemy_level','evo_new_species','fetched_species','saved_entry_h','saved_entry_l','old_max_hp_high','old_max_hp_low','loaded_max_hp_high','loaded_max_hp_low','loaded_hp_high','loaded_hp_low','saved_copy_b','saved_copy_c')+tuple('saved_'+x for x in REGISTERS)
ADDR={'tile_animations':0xffd7,'evolution_occurred':0xd121,'which_pokemon':0xcf92,'evo_old_species':0xcee9,'link_state':0xd12b,'force_evolution':0xccd4,'loaded_mon_level':0xcfb9,'cur_item':0xcf91,'is_in_battle':0xd057}
class Boundary(angr.SimProcedure):
 def __init__(self,c):super().__init__();self.c=c
 def run(self):self.state.globals['continuation']=claripy.BVV(self.c,8);self.jump(DONE)
class Read(angr.SimProcedure):
 def __init__(self,key,n,inc=False):super().__init__();self.key=key;self.n=n;self.inc=inc
 def run(self):self.state.regs.a=self.state.globals[self.key];self.state.regs.hl=self.state.regs.hl+(1 if self.inc else 0);self.jump(self.n)
class Write(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.jump(self.n)
class SaveAll(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  for z in REGISTERS:self.state.globals['saved_'+z]=(z80_flags_to_sm83(self.state.regs.f) if z=='f' else getattr(self.state.regs,z))
  self.jump(self.n)
class RestoreAll(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  for z in REGISTERS:setattr(self.state.regs,z,(sm83_flags_to_z80(self.state.globals['saved_f']) if z=='f' else self.state.globals['saved_'+z]))
  self.jump(self.n)
class PopParty(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.hl=0xd163;self.jump(self.n)
class IncWhich(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  old=self.state.globals['which_pokemon'];v=old+1;self.state.globals['which_pokemon']=v;self.state.regs.f=(self.state.regs.f&1)|claripy.If(v==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If((old&15)==15,claripy.BVV(0x10,8),claripy.BVV(0,8));self.jump(self.n)
class Music(angr.SimProcedure):
 def run(self):self.state.globals['music_called']=claripy.BVV(1,8);self.jump(DONE)
class XorA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=0;self.state.regs.f=claripy.BVV(0x40,8);self.jump(self.n)
class IncHL(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
class BranchZ(angr.SimProcedure):
 def __init__(self,z,nz):super().__init__();self.z=z;self.nz=nz
 def run(self):
  self.inhibit_autoret=True;c=(self.state.regs.f&0x40)!=0;self.successors.add_successor(self.state.copy(),self.z,c,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.nz,claripy.Not(c),'Ijk_Boring')
class SaveEntryHL(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['saved_entry_h']=self.state.regs.h;self.state.globals['saved_entry_l']=self.state.regs.l;self.jump(self.n)
class LoadValue(angr.SimProcedure):
 def __init__(self,key,n,inc=0):super().__init__();self.key=key;self.n=n;self.inc=inc
 def run(self):self.state.regs.a=self.state.globals[self.key];self.state.regs.hl=self.state.regs.hl+self.inc;self.jump(self.n)
class StoreValue(angr.SimProcedure):
 def __init__(self,key,n,inc=0):super().__init__();self.key=key;self.n=n;self.inc=inc
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.state.regs.hl=self.state.regs.hl+self.inc;self.jump(self.n)
class RestoreCopyBC(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.b=self.state.globals['saved_copy_b'];self.state.regs.c=self.state.globals['saved_copy_c'];self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'EvolutionAfterBattle');return angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address}),l.address
def setup(s,i):
 set_assembly_registers(s,i)
 for n in NAMES:s.globals[n]=i[n]
def ep(x):return E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[n] for n in NAMES)),continuation=x.globals.get('continuation',claripy.BVV(0,8)),constraints=tuple(x.solver.constraints))
def collect(m):
 m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr==DONE)
  if m.active:m.step()
 return [ep(x) for x in m.found]
def assembly_init(i):
 p,q=project();p.hook(q,Read('tile_animations',q+2),length=2);p.hook(q+2,SaveAll(q+3),length=1);p.hook(q+3,XorA(q+4),length=1);p.hook(q+4,Write('evolution_occurred',q+7),length=3);p.hook(q+7,Sm83DecRegister('a',q+8),length=1);p.hook(q+8,Write('which_pokemon',q+11),length=3);p.hook(q+17,Boundary(0),length=3);s=p.factory.blank_state(addr=q);setup(s,i);return collect(p.factory.simulation_manager(s))
def assembly_party(i):
 p,q=project();p.hook(q+0x15,IncWhich(q+0x16),length=1);p.hook(q+0x16,PopParty(q+0x17),length=1);p.hook(q+0x18,Read('party_species',q+0x19),length=1);p.hook(q+0x19,Sm83CpImmediate(0xff,q+0x1b),length=2);p.hook(q+0x1c2,Boundary(0),length=1);p.hook(q+0x1e,Write('evo_old_species',q+0x21),length=3);p.hook(q+0x21,Boundary(1),length=1);s=p.factory.blank_state(addr=q+0x12);setup(s,i);return collect(p.factory.simulation_manager(s))
def assembly_classify(i):
 p,q=project();p.hook(q+0x12,Boundary(0),length=1);p.hook(q+0x55,Read('evolution_type',q+0x56,True),length=1);p.hook(q+0x56,Sm83AndImmediate(0xff,q+0x57),length=1);p.hook(q+0x5a,Sm83CpImmediate(3,q+0x5c),length=2);p.hook(q+0x5e,Read('link_state',q+0x61),length=3);p.hook(q+0x61,Sm83CpImmediate(2,q+0x63),length=2);p.hook(q+0x66,Sm83CpImmediate(2,q+0x68),length=2);p.hook(q+0x6a,Read('force_evolution',q+0x6d),length=3);p.hook(q+0x6d,Sm83AndImmediate(0xff,q+0x6e),length=1);p.hook(q+0x71,Sm83CpImmediate(1,q+0x73),length=2);p.hook(q+0x75,Boundary(1),length=1);p.hook(q+0x88,Boundary(2),length=1);p.hook(q+0x91,Boundary(3),length=1);s=p.factory.blank_state(addr=q+0x55);setup(s,i);return collect(p.factory.simulation_manager(s))
def assembly_requirement(i,kind):
 p,q=project()
 if kind==1:
  p.hook(q+0x75,Read('link_state',q+0x78),length=3);p.hook(q+0x78,Sm83CpImmediate(2,q+0x7a),length=2);p.hook(q+0x7d,Read('requirement',q+0x7e,True),length=1);start=q+0x75
 elif kind==2:
  p.hook(q+0x88,Read('requirement',q+0x89,True),length=1);p.hook(q+0x8a,Read('cur_item',q+0x8d),length=3);p.hook(q+0x8d,Sm83CpRegister('b',q+0x8e),length=1);p.hook(q+0x91,Read('level_requirement',q+0x92,True),length=1);start=q+0x88
 else:
  p.hook(q+0x91,Read('level_requirement',q+0x92,True),length=1);start=q+0x91
 p.hook(q+0x7f,Read('loaded_mon_level',q+0x82),length=3);p.hook(q+0x82,Sm83CpRegister('b',q+0x83),length=1);p.hook(q+0x93,Read('loaded_mon_level',q+0x96),length=3);p.hook(q+0x96,Sm83CpRegister('b',q+0x97),length=1)
 p.hook(q+0x12,Boundary(0),length=1);p.hook(q+0x1bd,Boundary(1),length=1);p.hook(q+0x1be,Boundary(1),length=1);p.hook(q+0x9a,Boundary(2),length=1)
 s=p.factory.blank_state(addr=start);setup(s,i);return collect(p.factory.simulation_manager(s))
def assembly_mutation(i):
 p,q=project();p.hook(q+0x9a,Write('cur_enemy_level',q+0x9d),length=3);p.hook(q+0x9f,Write('evolution_occurred',q+0xa2),length=3);p.hook(q+0xa2,SaveEntryHL(q+0xa3),length=1);p.hook(q+0xa3,Read('fetched_species',q+0xa4),length=1);p.hook(q+0xa4,Write('evo_new_species',q+0xa7),length=3);p.hook(q+0xa7,Read('which_pokemon',q+0xaa),length=3);p.hook(q+0xad,Boundary(0),length=3);s=p.factory.blank_state(addr=q+0x9a);setup(s,i);return collect(p.factory.simulation_manager(s))
def assembly_next(i,first):
 p,q=project();start=0x1bd if first else 0x1be;p.hook(q+0x55,Boundary(0),length=1);s=p.factory.blank_state(addr=q+start);setup(s,i);return collect(p.factory.simulation_manager(s))
def assembly_adjust_hp(i):
 p,q=project();p.hook(q+0x15f,Sm83AddHlRegisterPair('bc',q+0x160),length=1);p.hook(q+0x160,LoadValue('old_max_hp_high',q+0x161,1),length=1);p.hook(q+0x162,LoadValue('old_max_hp_low',q+0x163),length=1);p.hook(q+0x166,LoadValue('loaded_max_hp_low',q+0x167,-1),length=1);p.hook(q+0x167,Sm83SubRegister('c',q+0x168),length=1);p.hook(q+0x16a,LoadValue('loaded_max_hp_high',q+0x16b),length=1);p.hook(q+0x16b,Sm83SbcRegister('b',q+0x16c),length=1);p.hook(q+0x170,LoadValue('loaded_hp_low',q+0x171),length=1);p.hook(q+0x171,Sm83AddRegister('c',q+0x172),length=1);p.hook(q+0x172,StoreValue('loaded_hp_low',q+0x173,-1),length=1);p.hook(q+0x174,LoadValue('loaded_hp_high',q+0x175),length=1);p.hook(q+0x175,Sm83AdcRegister('b',q+0x176),length=1);p.hook(q+0x176,StoreValue('loaded_hp_high',q+0x177),length=1);p.hook(q+0x178,RestoreCopyBC(DONE),length=1);s=p.factory.blank_state(addr=q+0x15c);setup(s,i);return collect(p.factory.simulation_manager(s))
def assembly_done(i):
 p,q=project();p.hook(q+0x1c2,RestoreAll(q+0x1c6),length=4);p.hook(q+0x1c6,Write('tile_animations',q+0x1c8),length=2);p.hook(q+0x1c8,Read('link_state',q+0x1cb),length=3);p.hook(q+0x1cb,Sm83CpImmediate(2,q+0x1cd),length=2);p.hook(q+0x1cd,BranchZ(DONE,q+0x1ce),length=1);p.hook(q+0x1ce,Read('is_in_battle',q+0x1d1),length=3);p.hook(q+0x1d1,Sm83AndImmediate(0xff,q+0x1d2),length=1);p.hook(q+0x1d2,BranchZ(q+0x1d3,DONE),length=1);p.hook(q+0x1d3,Read('evolution_occurred',q+0x1d6),length=3);p.hook(q+0x1d6,Sm83AndImmediate(0xff,q+0x1d7),length=1);p.hook(q+0x1d7,BranchZ(q+0x1da,q+0x1db),length=3);p.hook(q+0x1da,Boundary(0),length=1);p.hook(q+0x1db,Music(),length=1);s=p.factory.blank_state(addr=q+0x1c2);setup(s,i);return collect(p.factory.simulation_manager(s))
def native(name,i,returns=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=(x.regs.rax[7:0] if returns else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
def native_requirement(i,kind):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_evolution_check_requirement');s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE,kind);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=x.regs.rax[7:0],constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.parametrize('assembly,name,returns',((assembly_init,'port_evolution_after_battle_init',False),(assembly_party,'port_evolution_party_mon_begin',True),(assembly_classify,'port_evolution_classify_entry',True),(assembly_mutation,'port_evolution_begin_mutation',False),(lambda i:assembly_next(i,True),'port_evolution_next_entry1',False),(lambda i:assembly_next(i,False),'port_evolution_next_entry2',False),(assembly_done,'port_evolution_after_battle_done',False)))
def test_equivalence(assembly,name,returns):
 i=inputs(name);assert_pathwise_equivalent(assembly(i),native(name,i,returns),(*REGISTERS,'memory','continuation'))
@pytest.mark.parametrize('kind',(1,2,3))
def test_requirement(kind):
 i=inputs('requirement'+str(kind));assert_pathwise_equivalent(assembly_requirement(i,kind),native_requirement(i,kind),(*REGISTERS,'memory','continuation'))
def test_exact_body():
 a=symbol_location(SYMBOLS,'EvolutionAfterBattle');b=symbol_location(SYMBOLS,'RenameEvolvedMon');assert linked_bytes(ROM,a,b.address-a.address)==bytes.fromhex('f0d7f5afea21d13dea92cfe5c5d52163d1e52192cf34e1237efeffcade6eeae9cee5fa92cf4f21d3cc0602cd577079a7ca2e6dfae9ce3d0600215c7087cb104f092a666fe5fa91cff5afea49cccd7213f1ea91cfe12aa728b947fe032817fa2bd1fe3228ad78fe02281efad4cca720a278fe01281cfa2bd1fe32c2d96e2a47fab9cfb8da2e6d18122a47fa91cfb8c2d96e2a47fab9cfb8dada6eea27d13e01ea21d1e57eeaeacefa92cf21b5d2cdba15cd2638214d6fcd493c0e32cd3937afe0ba21a0c301140ccdc4183e01e0ba3effeacbcfcd820021e97d061ecdd635da2e6f213e6fcd493ce17eeab5d0ea98cfeaeace3e01eab6d03e0eeab7d0cd6b37e521436fcd593c3e89cd4037cd48370e28cd3937cd0f19cdf76efa1ed1f5fab5d0ea1ed13e3acd6d3efa1ed13d21de43011c00cd873a11b8d0cdb500fab5d0eab8d0f1ea1ed121a8cf11bacf0601cd3639fa92cf216bd1012c00cd873a5d54e5c5012200092a474e21bbcf3a914f7e9847219acf7e81327e88772bc1cdb500fab5d0ea1ed1afea49cccd5b6fe13e42cd6d3efa57d0a7cc526f3e3acd6d3efa1ed13d4f060121f7d2c5cd5770c1210ad3cd5770d1e1fa98cf77e56b6218012323c3716dd1c1e1f1e0d7fa2bd1fe32c8fa57d0a7c0fa21d1a7c40723c9')
