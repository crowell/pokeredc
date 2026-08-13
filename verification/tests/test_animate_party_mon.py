from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AddRegister,Sm83AndImmediate,Sm83CpImmediate,Sm83CpRegister,Sm83DecRegister,Sm83IncRegister,Sm83XorImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000
ADV=0xeff5;RESET=0xeff6;EDIT=0xeff7;REPEAT=0xeff8;DONE=0xeff9
NAMES=('current_menu_item','on_sgb','anim_counter','hp_color','speed_value','fetched','written','write_h','write_l','saved_b','saved_c','delay_dispatched')
class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
class Read(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)
class AddValue(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):
  left=self.state.regs.a;right=self.state.globals[self.key];wide=claripy.ZeroExt(1,left)+claripy.ZeroExt(1,right);result=wide[7:0];self.state.regs.a=result;self.state.regs.f=claripy.If(result==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If((left&15)+(right&15)>15,claripy.BVV(0x10,8),claripy.BVV(0,8))|claripy.ZeroExt(7,wide[8]);self.jump(self.n)
class SaveBC(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['saved_b']=self.state.regs.b;self.state.globals['saved_c']=self.state.regs.c;self.jump(self.n)
class RestoreBC(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.b=self.state.globals['saved_b'];self.state.regs.c=self.state.globals['saved_c'];self.jump(self.n)
class StoreTimer(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['anim_counter']=self.state.regs.a;self.jump(self.n)
class StoreWrite(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['written']=self.state.regs.a;self.state.globals['write_h']=self.state.regs.h;self.state.globals['write_l']=self.state.regs.l;self.jump(self.n)
class CopyStore(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['written']=self.state.regs.a;self.state.globals['write_h']=self.state.regs.d;self.state.globals['write_l']=self.state.regs.e;self.state.regs.de=self.state.regs.de+1;self.jump(self.n)
class CopyLoad(Read):
 def run(self):self.state.regs.a=self.state.globals[self.key];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
class CopyTail(angr.SimProcedure):
 def run(self):
  bc=self.state.regs.bc-1;self.state.regs.bc=bc;self.state.regs.a=bc[7:0];self.state.regs.a=self.state.regs.a|bc[15:8];self.state.regs.f=claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8));self.jump(DONE)
class DispatchDelay(angr.SimProcedure):
 def run(self):self.state.globals['delay_dispatched']=claripy.BVV(1,8);self.jump(DONE)
class XorA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=0;self.state.regs.f=claripy.BVV(0x40,8);self.jump(self.n)
class BranchZ3(angr.SimProcedure):
 def __init__(self,z,nz):super().__init__();self.z=z;self.nz=nz
 def run(self):
  self.inhibit_autoret=True;c=(self.state.regs.f&0x40)!=0;self.successors.add_successor(self.state.copy(),self.z,c,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.nz,claripy.Not(c),'Ijk_Boring')
class AddNTimes(angr.SimProcedure):
 def __init__(self,count,n):super().__init__();self.count=count;self.n=n
 def run(self):
  a=self.state.regs.a;f=claripy.BVV(0x10,8)|claripy.If(a==0,claripy.BVV(0x40,8),claripy.BVV(0,8));hl=self.state.regs.hl;bc=self.state.regs.bc
  for _ in range(self.count):
   wide=claripy.ZeroExt(1,hl)+claripy.ZeroExt(1,bc);low=claripy.ZeroExt(1,hl&0xfff)+claripy.ZeroExt(1,bc&0xfff);f=(f&0x40)|claripy.If(low>0xfff,claripy.BVV(0x10,8),claripy.BVV(0,8))|claripy.ZeroExt(7,wide[16]);hl=wide[15:0];old=a;a=a-1;f=(f&1)|claripy.BVV(2,8)|claripy.If(a==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If((old&15)==0,claripy.BVV(0x10,8),claripy.BVV(0,8))
  self.state.regs.a=a;self.state.regs.f=f;self.state.regs.hl=hl;self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'AnimatePartyMon');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
def setup(s,i):
 set_assembly_registers(s,i)
 for n in NAMES:s.globals[n]=i[n]
def ep(x,c):return E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[n] for n in NAMES)),continuation=(claripy.BVV(c,8) if isinstance(c,int) else c),constraints=tuple(x.solver.constraints))
def collect(m,targets):
 m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in targets)
  if m.active:m.step()
 return m.found
def assembly_setup(i):
 p,q=project();p.hook(q+3,Read('current_menu_item',q+6),length=3);p.hook(q+9,Sm83AddHlRegisterPair('bc',q+10),length=1);p.hook(q+10,Read('hp_color',q+11),length=1);p.hook(q+15,Sm83AddHlRegisterPair('bc',q+16),length=1);p.hook(q+16,Read('on_sgb',q+19),length=3);p.hook(q+19,Sm83XorImmediate(1,q+21),length=2);p.hook(q+21,AddValue('speed_value',q+22),length=1);p.hook(q+23,Sm83AddRegister('a',q+24),length=1);p.hook(q+25,Boundary(DONE),length=3);s=p.factory.blank_state(addr=q);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_select(i):
 p,q=project();p.hook(q+25,Read('anim_counter',q+28),length=3);p.hook(q+28,Sm83AndImmediate(0xff,q+29),length=1);p.hook(q+29,BranchZ3(RESET,q+31),length=2);p.hook(q+31,Sm83CpRegister('c',q+32),length=1);p.hook(q+32,BranchZ3(EDIT,ADV),length=2);s=p.factory.blank_state(addr=q+25);setup(s,i);ends=collect(p.factory.simulation_manager(s),{ADV,RESET,EDIT});codes={ADV:0,RESET:1,EDIT:2};return [ep(x,codes[x.addr]) for x in ends]
def assembly_advance(i):
 p,q=project();p.hook(q+34,Sm83IncRegister('a',q+35),length=1);p.hook(q+35,Sm83CpRegister('b',q+36),length=1);p.hook(q+36,BranchZ3(q+38,q+39),length=2);p.hook(q+38,XorA(q+39),length=1);p.hook(q+39,StoreTimer(q+42),length=3);p.hook(q+42,DispatchDelay(),length=3);s=p.factory.blank_state(addr=q+34);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_reset_begin(i):
 p,q=project();p.hook(q+45,SaveBC(q+46),length=1);p.hook(q+55,Boundary(DONE),length=3);s=p.factory.blank_state(addr=q+45);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_reset_copy(i):
 p,q=project();copy=symbol_location(SYMBOLS,'CopyData').address;p.hook(copy,CopyLoad('fetched',copy+1),length=1);p.hook(copy+1,CopyStore(copy+3),length=2);p.hook(copy+3,CopyTail(),length=5);s=p.factory.blank_state(addr=copy);setup(s,i);return [ep(x,claripy.If(x.regs.a==0,claripy.BVV(0,8),claripy.BVV(1,8))) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_reset_end(i):
 p,q=project();p.hook(q+58,RestoreBC(q+59),length=1);p.hook(q+59,XorA(DONE),length=1);s=p.factory.blank_state(addr=q+58);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_edit_begin(i,count):
 p,q=project();p.hook(q+62,SaveBC(q+63),length=1);p.hook(q+69,Read('current_menu_item',q+72),length=3);p.hook(q+72,AddNTimes(count,q+75),length=3);p.hook(q+77,Read('fetched',q+78),length=1);p.hook(q+78,Sm83CpImmediate(4,q+80),length=2);p.hook(q+80,BranchZ3(q+86,q+82),length=2);p.hook(q+82,Sm83CpImmediate(8,q+84),length=2);p.hook(q+84,BranchZ3(q+86,q+90),length=2);p.hook(q+95,Boundary(DONE),length=1);s=p.factory.blank_state(addr=q+62);setup(s,i);s.solver.add(i['current_menu_item']==count);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_edit_step(i):
 p,q=project();p.hook(q+95,Read('fetched',q+96),length=1);p.hook(q+96,Sm83AddRegister('c',q+97),length=1);p.hook(q+97,StoreWrite(q+98),length=1);p.hook(q+98,Sm83AddHlRegisterPair('de',q+99),length=1);p.hook(q+99,Sm83DecRegister('b',q+100),length=1);p.hook(q+100,BranchZ3(DONE,REPEAT),length=2);s=p.factory.blank_state(addr=q+95);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,DONE});return [ep(x,1 if x.addr==REPEAT else 0) for x in ends]
def assembly_edit_end(i):
 p,q=project();p.hook(q+102,RestoreBC(q+103),length=1);p.hook(q+104,Boundary(DONE),length=2);s=p.factory.blank_state(addr=q+102);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def native(name,i,returns,extra=()):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));s.solver.add(*extra);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=(x.regs.rax[7:0] if returns else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
CASES=((assembly_setup,'port_animate_party_mon_setup',False),(assembly_select,'port_animate_party_mon_select',True),(assembly_advance,'port_animate_party_mon_advance',False),(assembly_reset_begin,'port_animate_party_mon_reset_begin',False),(assembly_reset_copy,'port_animate_party_mon_reset_copy_step',True),(assembly_reset_end,'port_animate_party_mon_reset_end',False),(assembly_edit_step,'port_animate_party_mon_edit_step',True),(assembly_edit_end,'port_animate_party_mon_edit_end',False))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('assembly,name,returns',CASES)
def test_equivalence(assembly,name,returns):
 i=inputs(name);assert_pathwise_equivalent(assembly(i),native(name,i,returns),(*REGISTERS,'memory','continuation'))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('count',range(6))
def test_edit_begin(count):
 i=inputs('party_edit_begin_'+str(count));constraint=i['current_menu_item']==count;assert_pathwise_equivalent(assembly_edit_begin(i,count),native('port_animate_party_mon_edit_begin',i,False,(constraint,)),(*REGISTERS,'memory','continuation'))
def test_exact_body_and_table():
 l=symbol_location(SYMBOLS,'AnimatePartyMon');assert linked_bytes(ROM,l,106)==bytes.fromhex('211fcffa26cc4f0600097e4f21695709fa1bcfee01864f8747fa8bd0a7280eb9281c3cb82001afea8bd0c3af20c5215bcc1100c3016000cdb500c1af18e4c52102c3011000fa26cccd873a0e407efe042804fe0820042b2b0e0106041104007e8177190520f9c17918b8')
 t=symbol_location(SYMBOLS,'PartyMonSpeeds');assert linked_bytes(ROM,t,3)==bytes((5,16,32))
