from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AddRegister,Sm83BitRegister,Sm83CpImmediate,Sm83CpRegister,Sm83DecRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000
NO=0xeff2;YES=0xeff3;REPEAT=0xeff4;DONE=0xeff5
NAMES=('cable_destination','serial_status','status6','status3','last_map','last_blackout_map','destination_map','dungeon_destination','which_dungeon_warp','dungeon_entry_size','current_map','current_tileset','y_offset','x_offset','destination_warp_id','fetched0','fetched1','written','write_h','write_l')
class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
class Read(angr.SimProcedure):
 def __init__(self,key,n,inc=False):super().__init__();self.key=key;self.n=n;self.inc=inc
 def run(self):self.state.regs.a=self.state.globals[self.key];self.state.regs.hl=self.state.regs.hl+(1 if self.inc else 0);self.jump(self.n)
class Write(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.jump(self.n)
class WriteDE(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['written']=self.state.regs.a;self.state.globals['write_h']=self.state.regs.d;self.state.globals['write_l']=self.state.regs.e;self.jump(self.n)
class BitStatus(angr.SimProcedure):
 def __init__(self,bit,n,key='status6'):super().__init__();self.bit=bit;self.n=n;self.key=key
 def run(self):
  v=self.state.globals[self.key];self.state.regs.f=(self.state.regs.f&1)|0x10|claripy.If((v&(1<<self.bit))==0,claripy.BVV(0x40,8),claripy.BVV(0,8));self.jump(self.n)
class ResStatus(angr.SimProcedure):
 def __init__(self,bit,n,key='status6'):super().__init__();self.bit=bit;self.n=n;self.key=key
 def run(self):self.state.globals[self.key]&=~(1<<self.bit);self.jump(self.n)
class LoadHigh(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.h=self.state.globals['fetched1'];self.jump(self.n)
class XorA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=0;self.state.regs.f=claripy.BVV(0x40,8);self.jump(self.n)
class BranchZ(angr.SimProcedure):
 def __init__(self,z,nz):super().__init__();self.z=z;self.nz=nz
 def run(self):
  self.inhibit_autoret=True;c=(self.state.regs.f&0x40)!=0;self.successors.add_successor(self.state.copy(),self.z,c,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.nz,claripy.Not(c),'Ijk_Boring')
class DungeonAdvance(angr.SimProcedure):
 def run(self):
  self.state.regs.a=self.state.globals['dungeon_entry_size'];left=self.state.regs.a;right=self.state.regs.e;wide=claripy.ZeroExt(1,left)+claripy.ZeroExt(1,right);result=wide[7:0];self.state.regs.a=result;self.state.regs.f=claripy.If(result==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If((left&15)+(right&15)>15,claripy.BVV(0x10,8),claripy.BVV(0,8))|claripy.ZeroExt(7,wide[8]);self.state.regs.e=result;self.jump(REPEAT)
class FlyAdvance(angr.SimProcedure):
 def run(self):self.state.regs.hl=self.state.regs.hl+2;self.jump(REPEAT)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'LoadSpecialWarpData');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
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
def assembly_select(i):
 p,q=project();p.hook(q,Read('cable_destination',q+3),length=3);p.hook(q+3,Sm83CpImmediate(0xef,q+5),length=2);p.hook(q+10,Read('serial_status',q+12),length=2);p.hook(q+12,Sm83CpImmediate(2,q+14),length=2);p.hook(q+21,Sm83CpImmediate(0xf0,q+23),length=2);p.hook(q+28,Read('serial_status',q+30),length=2);p.hook(q+30,Sm83CpImmediate(2,q+32),length=2);p.hook(q+39,Read('status6',q+42),length=3);p.hook(q+42,Sm83BitRegister(1,'a',q+44),length=2);p.hook(q+46,Sm83BitRegister(2,'a',q+48),length=2);p.hook(q+53,Boundary(YES),length=5);p.hook(q+71,Boundary(NO),length=3);s=p.factory.blank_state(addr=q);setup(s,i);ends=collect(p.factory.simulation_manager(s),{NO,YES});return [ep(x,1 if x.addr==YES else 0) for x in ends]
def assembly_fixed_begin(i):
 p,q=project();p.hook(q+58,Boundary(DONE),length=1);s=p.factory.blank_state(addr=q+53);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_copy(i,start):
 p,q=project();p.hook(q+start,Read('fetched0',q+start+1,True),length=1);p.hook(q+start+1,WriteDE(q+start+2),length=1);p.hook(q+start+3,Sm83DecRegister('c',q+start+4),length=1);p.hook(q+start+4,Boundary(DONE),length=2);s=p.factory.blank_state(addr=q+start);setup(s,i);return [ep(x,claripy.If(x.regs.c==0,claripy.BVV(0,8),claripy.BVV(1,8))) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_fixed_end(i):
 p,q=project();p.hook(q+64,Read('fetched0',q+65,True),length=1);p.hook(q+65,Write('current_tileset',q+68),length=3);p.hook(q+68,XorA(DONE),length=1);s=p.factory.blank_state(addr=q+64);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_route(i):
 p,q=project();p.hook(q+71,Read('last_map',q+74),length=3);p.hook(q+77,BitStatus(4,q+79),length=2);p.hook(q+81,BitStatus(6,q+83),length=2);p.hook(q+83,ResStatus(6,q+85),length=2);p.hook(q+87,Read('last_blackout_map',q+90),length=3);p.hook(q+92,Boundary(YES),length=1);p.hook(q+143,Read('destination_map',q+146),length=3);p.hook(q+147,Write('current_map',q+150),length=3);p.hook(q+153,Boundary(NO),length=1);s=p.factory.blank_state(addr=q+71);setup(s,i);ends=collect(p.factory.simulation_manager(s),{NO,YES});return [ep(x,1 if x.addr==YES else 0) for x in ends]
def assembly_dungeon_begin(i):
 p,q=project();p.hook(q+95,ResStatus(4,q+97,'status3'),length=2);p.hook(q+97,Read('dungeon_destination',q+100),length=3);p.hook(q+101,Write('current_map',q+104),length=3);p.hook(q+104,Read('which_dungeon_warp',q+107),length=3);p.hook(q+116,Write('dungeon_entry_size',q+119),length=3);p.hook(q+119,Boundary(DONE),length=1);s=p.factory.blank_state(addr=q+92);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_dungeon_scan(i):
 p,q=project();p.hook(q+119,Read('fetched0',q+120,True),length=1);p.hook(q+120,Sm83CpRegister('b',q+121),length=1);p.hook(q+128,BranchZ(YES,q+130),length=2);p.hook(q+126,Read('fetched1',q+127,True),length=1);p.hook(q+127,Sm83CpRegister('c',q+128),length=1);p.hook(q+130,DungeonAdvance(),length=7);p.hook(q+137,Boundary(YES),length=1);s=p.factory.blank_state(addr=q+119);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,YES});return [ep(x,1 if x.addr==YES else 0) for x in ends]
def assembly_dungeon_found(i):
 p,q=project();p.hook(q+140,Sm83AddHlRegisterPair('de',q+141),length=1);p.hook(q+165,Boundary(DONE),length=3);s=p.factory.blank_state(addr=q+137);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_fly_scan(i):
 p,q=project();p.hook(q+153,Read('fetched0',q+154,True),length=1);p.hook(q+155,Sm83CpRegister('b',q+156),length=1);p.hook(q+156,BranchZ(YES,q+158),length=2);p.hook(q+158,FlyAdvance(),length=4);p.hook(q+162,Boundary(YES),length=1);s=p.factory.blank_state(addr=q+153);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,YES});return [ep(x,1 if x.addr==YES else 0) for x in ends]
def assembly_fly_found(i):
 p,q=project();p.hook(q+162,Read('fetched0',q+163,True),length=1);p.hook(q+163,LoadHigh(q+164),length=1);p.hook(q+165,Boundary(DONE),length=3);s=p.factory.blank_state(addr=q+162);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_generic_begin(i):
 p,q=project();p.hook(q+170,Boundary(DONE),length=1);s=p.factory.blank_state(addr=q+165);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_generic_end(i):
 p,q=project();p.hook(q+177,Write('current_tileset',DONE),length=3);s=p.factory.blank_state(addr=q+176);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def assembly_finish(i):
 p,q=project();p.hook(q+180,Write('y_offset',q+183),length=3);p.hook(q+183,Write('x_offset',q+186),length=3);p.hook(q+188,Write('destination_warp_id',DONE),length=3);s=p.factory.blank_state(addr=q+180);setup(s,i);return [ep(x,0) for x in collect(p.factory.simulation_manager(s),{DONE})]
def native(name,i,returns):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=(x.regs.rax[7:0] if returns else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
CASES=((assembly_select,'port_load_special_warp_select_fixed',True),(assembly_fixed_begin,'port_load_special_warp_fixed_begin',False),(lambda i:assembly_copy(i,58),'port_load_special_warp_copy_step',True),(assembly_fixed_end,'port_load_special_warp_fixed_end',False),(assembly_route,'port_load_special_warp_route_kind',True),(assembly_dungeon_begin,'port_load_special_warp_dungeon_begin',False),(assembly_dungeon_scan,'port_load_special_warp_dungeon_scan',True),(assembly_dungeon_found,'port_load_special_warp_dungeon_found',False),(assembly_fly_scan,'port_load_special_warp_fly_scan',True),(assembly_fly_found,'port_load_special_warp_fly_found',False),(assembly_generic_begin,'port_load_special_warp_generic_copy_begin',False),(assembly_generic_end,'port_load_special_warp_generic_end',False),(assembly_finish,'port_load_special_warp_finish',False))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('assembly,name,returns',CASES)
def test_equivalence(assembly,name,returns):
 i=inputs(name);assert_pathwise_equivalent(assembly(i),native(name,i,returns),(*REGISTERS,'memory','continuation'))
def test_exact_body_and_tables():
 l=symbol_location(SYMBOLS,'LoadSpecialWarpData');assert linked_bytes(ROM,l,192)==bytes.fromhex('fa2dd7feef200e212864f0aafe0228252130641820fef0200e213864f0aafe022813214064180efa32d7cb4f2019cb572015212064115ed30e072a12130d20fa2aea67d3af186dfa65d32132d7cb66200bcb76cbb62838fa19d71836212dd7cba6fa1dd747ea5ed3fa1ed74f21bf631100003e06ea2fd12ab828032318042ab92807fa2fd1835f18ee21d863191816fa1ad747ea5ed32148642a23b82804232318f72a666f115fd30e062a12130d20faafea67d3eae2d4eae3d43effea2fd4c9')
 checks=(('DungeonWarpList',25,'9f019f02a001a002a101a102a201a202c202a501a502d603ff'),('DungeonWarpData',72,'46c70712010048c70717010146c70713010148c70716010046c70712010046c70713010193c70e04000093c70e050001b1c71016000099c70e10000099c70e1000009ac70e120000'),('NewGameWarp',40,'2612c70603000104ef0bc70403000115ef0dc70406000015f00bc70403000115f00dc70406000015'),('FlyWarpDataPtr',130,'00007c64010082640200886403008e640400946405009a640600a0640700a6640800ac640900b2640a00b8640f00be641500c4642bc70605000160c81a1700015bc81a0d0001f6c7121300012ac7060300013cc7040b0001b7c70a29000178c81c1300015ec70c0b00012dc7060900018dc81e090001bac7060b00019ec7140b0001'))
 for name,size,data in checks:assert linked_bytes(ROM,symbol_location(SYMBOLS,name),size)==bytes.fromhex(data)
