from __future__ import annotations
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83DecRegister,Sm83IncRegister
from verification.tests.test_vblank_copy_double import Boundary,BranchZ,E,HlToSp,Load,PopDe,SpToHl,Store,WriteReg,ZeroA
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000
LOOP=0xeffb;REPEAT=0xeffc;DONE=0xeffd;RETURN=0xeffe
SCALARS=('sp_high','sp_low','temp_high','temp_low','source_low','source_high','dest_low','dest_high','size')
ARRAYS=tuple(f'{p}{i}' for p,n in (('source',16),('written',16),('write_h',16),('write_l',16)) for i in range(n));NAMES=SCALARS+ARRAYS
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'VBlankCopy');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
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
 p,q=project();p.hook(q,Load('size',q+2),length=2);p.hook(q+2,Sm83AndImmediate(0xff,q+3),length=1);p.hook(q+3,BranchZ(q+4),length=1);p.hook(q+4,SpToHl(q+6),length=2);p.hook(q+7,Store('temp_high',q+9),length=2);p.hook(q+10,Store('temp_low',q+12),length=2);p.hook(q+12,Load('source_low',q+14),length=2);p.hook(q+15,Load('source_high',q+17),length=2);p.hook(q+18,HlToSp(q+19),length=1);p.hook(q+19,Load('dest_low',q+21),length=2);p.hook(q+22,Load('dest_high',q+24),length=2);p.hook(q+25,Load('size',q+27),length=2);p.hook(q+28,ZeroA(q+29),length=1);p.hook(q+29,Store('size',q+31),length=2);p.hook(q+31,Boundary(LOOP),length=1);s=p.factory.blank_state(addr=q);setup(s,i);ends=collect(p.factory.simulation_manager(s),{RETURN,LOOP});return [ep(x,0 if x.addr==RETURN else 1) for x in ends]
def assembly_step(i):
 p,q=project()
 for pair in range(8):
  base=31+pair*5;idx=pair*2;p.hook(q+base,PopDe(idx,q+base+1,loop=pair==0),length=1);p.hook(q+base+1,WriteReg(idx,'e',q+base+2),length=1);p.hook(q+base+2,Sm83IncRegister('l',q+base+3),length=1);p.hook(q+base+3,WriteReg(idx+1,'d',q+base+4),length=1)
  if pair<7:p.hook(q+base+4,Sm83IncRegister('l',q+base+5),length=1)
 p.hook(q+71,Sm83DecRegister('b',q+72),length=1);p.hook(q+75,Store('dest_low',q+77),length=2);p.hook(q+78,Store('dest_high',q+80),length=2);p.hook(q+80,SpToHl(q+82),length=2);p.hook(q+83,Store('source_low',q+85),length=2);p.hook(q+86,Store('source_high',q+88),length=2);p.hook(q+88,Load('temp_high',q+90),length=2);p.hook(q+91,Load('temp_low',q+93),length=2);p.hook(q+94,HlToSp(q+95),length=1);p.hook(q+95,Boundary(DONE),length=1);s=p.factory.blank_state(addr=q+31);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,DONE});return [ep(x,1 if x.addr==REPEAT else 0) for x in ends]
def native(name,i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=x.regs.rax[7:0],constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('assembly,name',((assembly_setup,'port_vblank_copy_setup'),(assembly_step,'port_vblank_copy_step')))
def test_equivalence(assembly,name):
 i=inputs(name);assert_pathwise_equivalent(assembly(i),native(name,i),(*REGISTERS,'memory','continuation'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'VBlankCopy');assert linked_bytes(ROM,l,96)==bytes.fromhex('f0c6a7c8f8007ce0bf7de0c0f0c76ff0c867f9f0c96ff0ca67f0c647afe0c6d1732c722cd1732c722cd1732c722cd1732c722cd1732c722cd1732c722cd1732c722cd1732c72230520d57de0c97ce0caf8007de0c77ce0c8f0bf67f0c06ff9c9')
