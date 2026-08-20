from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;DONE=0xEFFF
FIELDS=('requested_bank','loaded_bank','rom_bank','copy_a','copy_f','copy_b','copy_c','copy_d','copy_e','copy_h','copy_l')
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
 requested_bank:claripy.ast.BV;loaded_bank:claripy.ast.BV;rom_bank:claripy.ast.BV;copy_a:claripy.ast.BV;copy_f:claripy.ast.BV;copy_b:claripy.ast.BV;copy_c:claripy.ast.BV;copy_d:claripy.ast.BV;copy_e:claripy.ast.BV;copy_h:claripy.ast.BV;copy_l:claripy.ast.BV
 constraints:tuple[claripy.ast.Bool,...]
class StoreRequested(angr.SimProcedure):
 def run(self)->None:self.state.globals['requested_bank']=self.state.regs.a;self.jump(self.state.addr+2)
class LoadField(angr.SimProcedure):
 def __init__(self,field,next_address,length):super().__init__();self.field=field;self.next_address=next_address;self.length=length
 def run(self)->None:self.state.regs.a=self.state.globals[self.field];self.jump(self.next_address)
class PushNoOp(angr.SimProcedure):
 def run(self)->None:self.jump(self.state.addr+1)
class BranchNZ(angr.SimProcedure):
 def __init__(self,taken,fallthrough):super().__init__();self.taken=taken;self.fallthrough=fallthrough
 def run(self)->None:
  self.inhibit_autoret=True;c=(self.state.regs.f&0x40)==0;self.successors.add_successor(self.state.copy(),self.taken,c,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.fallthrough,claripy.Not(c),'Ijk_Boring')
class LoadOne(angr.SimProcedure):
 def run(self)->None:self.state.regs.a=1;self.jump(self.state.addr+2)
class LoadFifteen(angr.SimProcedure):
 def run(self)->None:self.state.regs.a=15;self.jump(self.state.addr+2)
class SetRomBank(angr.SimProcedure):
 def run(self)->None:self.state.globals['rom_bank']=self.state.regs.a;self.state.globals['loaded_bank']=self.state.regs.a;self.jump(self.state.addr+5)
class CopyDataSummary(angr.SimProcedure):
 def run(self)->None:
  for r,f in (('a','copy_a'),('b','copy_b'),('c','copy_c'),('d','copy_d'),('e','copy_e'),('h','copy_h'),('l','copy_l')):setattr(self.state.regs,r,self.state.globals[f])
  self.state.regs.f=sm83_flags_to_z80(self.state.globals['copy_f']);self.jump(self.state.addr+3)
class PopAF(angr.SimProcedure):
 def run(self)->None:self.state.regs.a=self.state.globals['loaded_bank_original'];self.state.regs.f=self.state.globals['input_f_z80'];self.jump(self.state.addr+1)
class RestoreBank(angr.SimProcedure):
 def run(self)->None:self.state.globals['loaded_bank']=self.state.globals['loaded_bank_original'];self.state.globals['rom_bank']=self.state.globals['loaded_bank_original'];self.jump(self.state.addr+5)
class Boundary(angr.SimProcedure):
 def run(self)->None:self.jump(DONE)
def _assembly(i):
 l=symbol_location(SYMBOLS,'FarCopyData2');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q})
 p.hook(q,StoreRequested(),length=2);p.hook(q+2,LoadField('loaded_bank',q+4,2),length=2);p.hook(q+4,PushNoOp(),length=1);p.hook(q+5,LoadField('requested_bank',q+7,2),length=2);p.hook(q+7,SetRomBank(),length=5);p.hook(q+12,CopyDataSummary(),length=3);p.hook(q+15,PopAF(),length=1);p.hook(q+16,RestoreBank(),length=5);p.hook(q+21,Boundary(),length=1)
 s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for f in FIELDS:s.globals[f]=i[f]
 s.globals['loaded_bank_original']=i['loaded_bank'];s.globals['input_f_z80']=s.regs.f;m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=1);assert len(m.found)==1
 return [Endpoint(**assembly_registers(x),**{f:x.globals[f] for f in FIELDS},constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_far_copy_data2');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for off,f in enumerate(FIELDS,8):s.memory.store(NATIVE_STATE+off,i[f])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1
 return [Endpoint(**native_registers(x,NATIVE_STATE),**{f:x.memory.load(NATIVE_STATE+off,1) for off,f in enumerate(FIELDS,8)},constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_far_copy_data2_pathwise_equivalence():
 i=symbolic_registers('fcd2');i['requested_bank']=i['a'];i['loaded_bank']=claripy.BVS('fcd2_loaded_bank',8);i['rom_bank']=claripy.BVS('fcd2_rom_bank',8)
 for f in ('copy_a','copy_b','copy_c','copy_d','copy_e','copy_h','copy_l'):i[f]=claripy.BVS('fcd2_'+f,8)
 i['copy_f']=claripy.Concat(claripy.BVS('fcd2_copy_flags',4),claripy.BVV(0,4))
 assert_pathwise_equivalent(_assembly(i),_native(i),('a','f','b','c','d','e','h','l',*FIELDS))
def test_far_copy_data2_exact_body():
 l=symbol_location(SYMBOLS,'FarCopyData2');assert linked_bytes(ROM,l,22)==bytes.fromhex('e08bf0b8f5f08be0b8ea0020cdb500f1e0b8ea0020c9')
