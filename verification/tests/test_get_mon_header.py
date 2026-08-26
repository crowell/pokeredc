from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83CpImmediate,Sm83CpRegister,Sm83DecRegister,Sm83LoadAAtHlDecrement,Sm83LoadAAtHlIncrement,Sm83LoadAImmediate,Sm83LoadAHighImmediate,Sm83OrRegister,Sm83RrRegister,Sm83SetAtHl,Sm83SrlRegister,Sm83StoreAAtHlIncrement,Sm83StoreAImmediate,Sm83StoreAHighImmediate,Sm83LoadABytePreserveF,Sm83XorA,Sm83LdAFromRegPreserveF
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;STACK=0xd000;RETURN=0xffff
DEX=0xd11e;CUR=0xd0b5;HDR=0xd0b8;HDRN=28;BANKR=0xffb8;ROMB=0x2000
SPECIALS=(0x15,0xB6,0xB7,0xB8)
TABLE_HEX='707320231564225002676c66585e1d1f686f833b97825a485c7b78097f7200003a5f16104f404b71437a6a6b182f36604c007e007d526d0038563280000000533095000000543c7c9290918434620000002526191a000093948c8d747500001b1c8a8b2728858887864229172e3d3e0d0e0f00553933315700000a0b0c440037612a968f8100005900635b0065246e3569005d3f41111279010349007677000000004d4e1314211e4a898e005100000407050806000000002b2c2d454647'
TABLE=bytes.fromhex(TABLE_HEX)
EXPECTED=bytes.fromhex('f0b8f53e0ee0b8ea0020c5d5e5fa1ed1f5fab5d0ea1ed111e8790666feb6283111b566feb8282a1136650677feb72821fe1528273e3acd6d3efa1ed13d011c0021de43cd873a11b8d0011c00cdb500181821c2d07023732372180e215b4211b8d0011c003e01cd9d00fab5d0eab8d0f1ea1ed1e1d1c1f1e0b8ea0020c9')
SPECIES_CASES=[s for s in range(1,191) if s not in SPECIALS]+list(SPECIALS)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
 dex:claripy.ast.BV;hdr:claripy.ast.BV;banks:claripy.ast.BV
 ccb:claripy.ast.BV;fcb:claripy.ast.BV
 constraints:tuple[claripy.ast.Bool,...]
def _sum(a,bc,hl0):
 hl0e=claripy.ZeroExt(9,hl0);bce=claripy.ZeroExt(9,bc);ae=claripy.ZeroExt(17,a)
 total=hl0e+ae*bce
 prev=claripy.ZeroExt(16,(hl0e+(ae-1)*bce)[15:0])
 return total[15:0],prev+claripy.ZeroExt(7,bce)
class PredefSite(angr.SimProcedure):
 """IndexToPokedex composition boundary at the call site: the proven port's
 `fetched` ordering-table byte is pinned to this case's concrete value."""
 def __init__(self,next_address:int,dex:int)->None:
  super().__init__();self._next=next_address;self._dex=dex
 def run(self):
  self.state.memory.store(DEX,claripy.BVV(self._dex,8))
  self.jump(self._next)
class AAddN(angr.SimProcedure):
 """Proven AddNTimes composition boundary at the call site."""
 def __init__(self,next_address:int)->None:
  super().__init__();self._next=next_address
 def run(self):
  r=assembly_registers(self.state);self.state.globals['ccb']=claripy.Concat(*(r[x] for x in REGISTERS))
  hl,carry=_sum(r['a'],claripy.Concat(r['b'],r['c']),claripy.Concat(r['h'],r['l']))
  self.state.regs.a=claripy.BVV(0,8)
  self.state.regs.f=claripy.If(r['a']==0,claripy.BVV(0x50,8),claripy.BVV(0x42,8)|claripy.If(carry>0xffff,claripy.BVV(1,8),claripy.BVV(0,8)))
  self.state.regs.hl=hl
  self.jump(self._next)
class NAddN(angr.SimProcedure):
 def run(self,s):
  self.state.globals['ccb']=self.state.memory.load(s,8)
  a=self.state.memory.load(s,1);bc=claripy.Concat(self.state.memory.load(s+2,1),self.state.memory.load(s+3,1));hl0=claripy.Concat(self.state.memory.load(s+6,1),self.state.memory.load(s+7,1))
  hl,carry=_sum(a,bc,hl0)
  f_canon=claripy.If(a==0,claripy.BVV(0xa0,8),claripy.BVV(0xc0,8)|claripy.If(carry>0xffff,claripy.BVV(0x10,8),claripy.BVV(0,8)))
  self.state.memory.store(s,claripy.Concat(claripy.BVV(0,8),f_canon,self.state.memory.load(s+2,4),hl[15:8],hl[7:0]))
class ACopy(angr.SimProcedure):
 """Proven CopyData composition boundary at the call site: the 28 copied
 header bytes are the callee's own proven domain (arbitrary here)."""
 def __init__(self,next_address:int)->None:
  super().__init__();self._next=next_address
 def run(self):
  r=assembly_registers(self.state);self.state.globals['ccb']=claripy.Concat(*(r[x] for x in REGISTERS))
  for i in range(HDRN):self.state.memory.store(HDR+i,self.state.globals[f'cob{i}'])
  self.jump(self._next)
class NCopy(angr.SimProcedure):
 def run(self,s,m):
  self.state.globals['ccb']=self.state.memory.load(s,8)
  for i in range(HDRN):self.state.memory.store(m+HDR+i,self.state.globals[f'cob{i}'])
class AFarCopy(angr.SimProcedure):
 """Proven FarCopyData composition boundary at the call site (the .mew
 path): the 28 copied header bytes are arbitrary here."""
 def __init__(self,next_address:int)->None:
  super().__init__();self._next=next_address
 def run(self):
  r=assembly_registers(self.state);self.state.globals['fcb']=claripy.Concat(*(r[x] for x in REGISTERS))
  for i in range(HDRN):self.state.memory.store(HDR+i,self.state.globals[f'fob{i}'])
  self.jump(self._next)
class NFarCopy(angr.SimProcedure):
 def run(self,s,m):
  self.state.globals['fcb']=self.state.memory.load(s,8)
  for i in range(HDRN):self.state.memory.store(m+HDR+i,self.state.globals[f'fob{i}'])
def inputs(p):
 v=symbolic_registers(p)
 v['dex']=claripy.BVS(p+'_dex',8)
 for i in range(HDRN):v[f'h{i}']=claripy.BVS(f'{p}_h{i}',8)
 v['bank']=claripy.BVS(p+'_bank',8);v['romb']=claripy.BVS(p+'_romb',8)
 for i in range(HDRN):v[f'cob{i}']=claripy.BVS(f'{p}_cob{i}',8)
 for i in range(HDRN):v[f'fob{i}']=claripy.BVS(f'{p}_fob{i}',8)
 return v
def setup(s,v,species:int,native:bool):
 o=NM if native else 0
 s.memory.store(o+CUR,claripy.BVV(species,8))
 s.memory.store(o+DEX,v['dex'])
 for i in range(HDRN):s.memory.store(o+HDR+i,v[f'h{i}'])
 s.memory.store(o+BANKR,v['bank']);s.memory.store(o+ROMB,v['romb'])
 for i in range(HDRN):
  s.globals[f'cob{i}']=v[f'cob{i}'];s.globals[f'fob{i}']=v[f'fob{i}']
 s.globals['ccb']=None;s.globals['fcb']=None
def assembly(v,species:int):
 l=symbol_location(SYMS,'GetMonHeader');gp=symbol_location(SYMS,'Predef');an=symbol_location(SYMS,'AddNTimes');cd=symbol_location(SYMS,'CopyData');fc=symbol_location(SYMS,'FarCopyData')
 assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 dex=TABLE[species-1]
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+0,Sm83LoadAHighImmediate(0xb8,b+2),length=2)      # ldh a,[hLoadedROMBank]
 p.hook(b+5,Sm83StoreAHighImmediate(0xb8,b+7),length=2)     # ldh [hLoadedROMBank],a
 p.hook(b+7,Sm83StoreAImmediate(ROMB,b+10),length=3)        # ld [rROMB],a
 p.hook(b+13,Sm83LoadAImmediate(DEX,b+16),length=3)         # ld a,[wPokedexNum]
 p.hook(b+17,Sm83LoadAImmediate(CUR,b+20),length=3)         # ld a,[wCurSpecies]
 p.hook(b+20,Sm83StoreAImmediate(DEX,b+23),length=3)        # ld [wPokedexNum],a
 p.hook(b+28,Sm83CpImmediate(0xb6,b+30),length=2)           # cp FOSSIL_KABUTOPS
 p.hook(b+35,Sm83CpImmediate(0xb8,b+37),length=2)           # cp MON_GHOST
 p.hook(b+44,Sm83CpImmediate(0xb7,b+46),length=2)           # cp FOSSIL_AERODACTYL
 p.hook(b+48,Sm83CpImmediate(0x15,b+50),length=2)           # cp MEW
 p.hook(b+54,PredefSite(b+57,dex),length=3)                 # call Predef (IndexToPokedex)
 p.hook(b+57,Sm83LoadAImmediate(DEX,b+60),length=3)         # ld a,[wPokedexNum]

 p.hook(b+100,Sm83LoadABytePreserveF(b+101,b+102),length=2)  # ld a,BANK(MewBaseStats) (3E 01)
 p.hook(b+105,Sm83LoadAImmediate(CUR,b+108),length=3)        # .done: ld a,[wCurSpecies]
 p.hook(b+108,Sm83StoreAImmediate(HDR,b+111),length=3)       # ld [wMonHIndex],a
 p.hook(b+112,Sm83StoreAImmediate(DEX,b+115),length=3)       # ld [wPokedexNum],a
 p.hook(b+119,Sm83StoreAHighImmediate(0xb8,b+121),length=2)  # ldh [hLoadedROMBank],a
 p.hook(b+121,Sm83StoreAImmediate(ROMB,b+124),length=3)      # ld [rROMB],a
 p.hook(b+60,Sm83DecRegister('a',b+61),length=1)           # dec a
 p.hook(b+67,AAddN(b+70),length=3)     # call AddNTimes
 p.hook(b+76,ACopy(b+79),length=3)     # call CopyData
 p.hook(b+102,AFarCopy(b+105),length=3)  # call FarCopyData (.mew)
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v,species,False);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(s);m.explore(find=lambda st:st.addr==RETURN,num_find=64);assert not m.errored and len(m.found)==1
 return [E(**assembly_registers(x),dex=x.memory.load(DEX,1),hdr=claripy.Concat(*(x.memory.load(HDR+i,1) for i in range(HDRN))),banks=claripy.Concat(x.memory.load(BANKR,1),x.memory.load(ROMB,1)),ccb=(x.globals['ccb'] if x.globals['ccb'] is not None else claripy.BVV(0,8*len(REGISTERS))),fcb=(x.globals['fcb'] if x.globals['fcb'] is not None else claripy.BVV(0,8*len(REGISTERS))),constraints=tuple(x.solver.constraints)) for x in m.found]
def native(v,species:int):
 p=angr.Project(ELF,auto_load_libs=False)
 an=p.loader.find_symbol('port_add_n_times');cd=p.loader.find_symbol('port_copy_data');fc=p.loader.find_symbol('port_far_copy_data');assert an is not None and cd is not None and fc is not None
 p.hook(an.rebased_addr,NAddN());p.hook(cd.rebased_addr,NCopy());p.hook(fc.rebased_addr,NFarCopy())
 f=p.loader.find_symbol('port_get_mon_header');assert f
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v,species,True)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1
 return [E(**native_registers(x,NS),dex=x.memory.load(NM+DEX,1),hdr=claripy.Concat(*(x.memory.load(NM+HDR+i,1) for i in range(HDRN))),banks=claripy.Concat(x.memory.load(NM+BANKR,1),x.memory.load(NM+ROMB,1)),ccb=(x.globals['ccb'] if x.globals['ccb'] is not None else claripy.BVV(0,8*len(REGISTERS))),fcb=(x.globals['fcb'] if x.globals['fcb'] is not None else claripy.BVV(0,8*len(REGISTERS))),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
@pytest.mark.parametrize('species',SPECIES_CASES)
def test_get_mon_header_pathwise_equivalence(species):
 v=inputs('get_mon_header')
 assert linked_bytes(ROM,symbol_location(SYMS,'PokedexOrder'),190)==TABLE
 assert_pathwise_equivalent(assembly(v,species),native(v,species),(*REGISTERS,'dex','hdr','banks','ccb','fcb'))
