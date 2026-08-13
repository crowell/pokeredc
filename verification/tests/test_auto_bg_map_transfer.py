from __future__ import annotations
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AndImmediate,Sm83DecRegister,Sm83IncRegister
from verification.tests.test_vblank_copy_bg_map import Boundary,BranchZ,E,HlToSp,Load,PopDe,SpToHl,Store,WriteReg,ZeroA
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000
ROW=0xeffb;REPEAT=0xeffc;DONE=0xeffd;RETURN=0xeffe
SCALARS=('sp_high','sp_low','temp_high','temp_low','enabled','portion','dest_low','dest_high')
ARRAYS=tuple(f'{p}{i}' for p in ('source','written','write_h','write_l') for i in range(20));NAMES=SCALARS+ARRAYS
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project(sym):
 l=symbol_location(SYMBOLS,sym);p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
def setup(s,i):
 set_assembly_registers(s,i)
 for n in NAMES:s.globals[n]=i[n]
def ep(x,c):return E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[n] for n in NAMES)),continuation=claripy.BVV(c,8),constraints=tuple(x.solver.constraints))
def collect(m,targets):
 m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in targets)
  if m.active:m.step()
 return m.found
def assembly_setup(i):
 p,q=project('AutoBgMapTransfer');p.hook(q,Load('enabled',q+2),length=2);p.hook(q+2,Sm83AndImmediate(0xff,q+3),length=1);p.hook(q+3,BranchZ(q+4),length=1);p.hook(q+4,SpToHl(q+6),length=2);p.hook(q+7,Store('temp_high',q+9),length=2);p.hook(q+10,Store('temp_low',q+12),length=2);p.hook(q+12,Load('portion',q+14),length=2);p.hook(q+14,Sm83AndImmediate(0xff,q+15),length=1);p.hook(q+17,Sm83DecRegister('a',q+18),length=1);p.hook(q+23,HlToSp(q+24),length=1);p.hook(q+24,Load('dest_high',q+26),length=2);p.hook(q+27,Load('dest_low',q+29),length=2);p.hook(q+33,Sm83AddHlRegisterPair('de',q+34),length=1);p.hook(q+34,ZeroA(q+35),length=1);p.hook(q+40,HlToSp(q+41),length=1);p.hook(q+41,Load('dest_high',q+43),length=2);p.hook(q+44,Load('dest_low',q+46),length=2);p.hook(q+54,HlToSp(q+55),length=1);p.hook(q+55,Load('dest_high',q+57),length=2);p.hook(q+58,Load('dest_low',q+60),length=2);p.hook(q+64,Sm83AddHlRegisterPair('de',q+65),length=1);p.hook(q+67,Store('portion',q+69),length=2);p.hook(q+71,Boundary(ROW),length=1);s=p.factory.blank_state(addr=q);setup(s,i);ends=collect(p.factory.simulation_manager(s),{RETURN,ROW});return [ep(x,0 if x.addr==RETURN else 1) for x in ends]
def assembly_row(i):
 p,q=project('TransferBgRows')
 for pair in range(10):
  off=pair*5;idx=pair*2;p.hook(q+off,PopDe(idx,q+off+1,loop=pair==0),length=1);p.hook(q+off+1,WriteReg(idx,'e',q+off+2),length=1);p.hook(q+off+2,Sm83IncRegister('l',q+off+3),length=1);p.hook(q+off+3,WriteReg(idx+1,'d',q+off+4),length=1)
  if pair<9:p.hook(q+off+4,Sm83IncRegister('l',q+off+5),length=1)
 from verification.harness.sm83_shims import Sm83AddRegister
 p.hook(q+51,Sm83AddRegister('l',q+52),length=1);p.hook(q+55,Sm83IncRegister('h',q+56),length=1);p.hook(q+56,Sm83DecRegister('b',q+57),length=1);p.hook(q+59,Load('temp_high',q+61),length=2);p.hook(q+62,Load('temp_low',q+64),length=2);p.hook(q+65,HlToSp(q+66),length=1);p.hook(q+66,Boundary(DONE),length=1);s=p.factory.blank_state(addr=q);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,DONE});return [ep(x,1 if x.addr==REPEAT else 0) for x in ends]
def native(name,i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=x.regs.rax[7:0],constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('assembly,name',((assembly_setup,'port_auto_bg_map_transfer_setup'),(assembly_row,'port_auto_bg_map_transfer_row_step')))
def test_equivalence(assembly,name):
 i=inputs(name);assert_pathwise_equivalent(assembly(i),native(name,i),(*REGISTERS,'memory','continuation'))
def test_exact_bodies():
 a=symbol_location(SYMBOLS,'AutoBgMapTransfer');assert linked_bytes(ROM,a,71)==bytes.fromhex('f0baa7c8f8007ce0bf7de0c0f0bba728143d281f2190c4f9f0bd67f0bc6f11800119af181e21a0c3f9f0bd67f0bc6f3e0118102118c4f9f0bd67f0bc6f11c000193e02e0bb0606');b=symbol_location(SYMBOLS,'TransferBgRows');assert linked_bytes(ROM,b,67)==bytes.fromhex('d1732c722cd1732c722cd1732c722cd1732c722cd1732c722cd1732c722cd1732c722cd1732c722cd1732c722cd1732c723e0d856f3001240520c5f0bf67f0c06ff9c9')
