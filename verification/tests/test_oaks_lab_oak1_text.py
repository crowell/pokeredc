from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location,z80_flags_to_sm83
from verification.harness.sm83_shims import Sm83CpImmediate,Sm83LoadAFromRegister,Sm83LoadAImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;DONE=0xefff
PALLET=0xd747;LAB=0xd74b;ROUTE=0xd7eb;STATUS=0xd72e;NUM=0xd11e;TEXTCTL=0xcc3c;SCRIPT=0xd5f0;TEXTBOX=0xd125;LOADED=0xffb8;ROMB=0x2000
PREDEF=(0xcc4e,0xcc4f,0xcc50,0xcc51,0xcc52,0xcc53,0xcc54,0xcf12,0xd0b7)
MEMORY=(PALLET,LAB,ROUTE,STATUS,NUM,TEXTCTL,SCRIPT,TEXTBOX,LOADED,ROMB,*PREDEF)
EXPECTED=bytes.fromhex('fa47d7cb77201621f7d20613cd7f2bfa1ed1fe02381afa4bd7cb6f2813211d53cd493c3e01ea3ccc3e56cd6d3ec3ed520604cd93342067faebd7cb6f2049fa4bd7cb6f203acb5f2017fa2ed7cb5f200821f052cd493c184c21f552cd493c18440646cd9334200821fa52cd493c183521ff52cd493ccd0a503e0feaf0d51825210953cd493c181d214bd7cb66cbe6200e010504cd2e3e210e53cd493c1806211853cd493cc3d724')
SCENARIOS=(
 ('pallet-rating',0x40,0,0,0,0,(),0x531d),('owned-rating',0,0x20,0,0,2,(),0x531d),
 ('has-ball',0,0,0,0,0,(1,),0x5318),('reward-already',0,0x10,0x20,0,0,(0,),0x5318),
 ('reward',0,0,0x20,0,0,(0,),0x530e),('world',0,0x20,0,0,0,(0,),0x5309),
 ('choose',0,0,0,0,0,(0,),0x52f0),('can-fight',0,0,0,8,0,(0,),0x52f5),
 ('raise',0,8,0,0,0,(0,0),0x52fa),('parcel',0,8,0,0,0,(0,1),0x52ff),)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
 state:claripy.ast.BV;memory:claripy.ast.BV;calls:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def setregs(s,vals):
 for n,v in zip(REGISTERS,vals,strict=True):setattr(s.regs,n,sm83_flags_to_z80(v) if n=='f' else v)
def amem(s):return claripy.Concat(*(s.memory.load(x,1) for x in MEMORY))
def nmem(s):return claripy.Concat(*(s.memory.load(NM+x,1) for x in MEMORY))
class Jump(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.inhibit_autoret=True;self.jump(self.n)
class LoadHL(angr.SimProcedure):
 def __init__(self,v,n):super().__init__();self.v=v;self.n=n
 def run(self):self.inhibit_autoret=True;self.state.regs.h=claripy.BVV(self.v>>8,8);self.state.regs.l=claripy.BVV(self.v&255,8);self.jump(self.n)
class BitA(angr.SimProcedure):
 def __init__(self,b,n):super().__init__();self.b=b;self.n=n
 def run(self):
  self.inhibit_autoret=True;z=((self.state.regs.a>>self.b)&1)==0;self.state.regs.f=(self.state.regs.f&1)|0x10|claripy.If(z,claripy.BVV(0x40,8),claripy.BVV(0,8));self.jump(self.n)
class CheckAndSet(angr.SimProcedure):
 def run(self):
  self.inhibit_autoret=True;prior=self.state.memory.load(LAB,1);z=(prior&0x10)==0;self.state.regs.f=(self.state.regs.f&1)|0x10|claripy.If(z,claripy.BVV(0x40,8),claripy.BVV(0,8));self.state.memory.store(LAB,prior|0x10);self.jump(0x52d7)
class LoadBC(angr.SimProcedure):
 def run(self):self.inhibit_autoret=True;self.state.regs.b=4;self.state.regs.c=5;self.jump(0x52dc)
class CountA(angr.SimProcedure):
 def __init__(self,count):super().__init__();self.count=count
 def run(self):
  self.inhibit_autoret=True;r=assembly_registers(self.state);self.state.globals['countcall']=claripy.Concat(*(r[x] for x in REGISTERS));c=claripy.BVV(self.count,8);self.state.regs.a=c;self.state.regs.f=sm83_flags_to_z80(claripy.BVV(0xc0,8));self.state.regs.b=0;self.state.regs.c=c;self.state.regs.d=0;self.state.regs.e=0;self.state.regs.h=0xd3;self.state.regs.l=0x0a;self.state.memory.store(NUM,c);self.jump(0x5258)
class IsA(angr.SimProcedure):
 def __init__(self,present,key,n):super().__init__();self.present=present;self.key=key;self.n=n
 def run(self):
  self.inhibit_autoret=True;r=assembly_registers(self.state);self.state.globals[self.key]=claripy.Concat(*(r[x] for x in REGISTERS));q=claripy.BVV(1 if self.present else 0,8);self.state.regs.a=q;self.state.regs.b=q;self.state.regs.f=sm83_flags_to_z80(claripy.BVV(0x20|(0x80 if not self.present else 0),8));self.jump(self.n)
class PrintA(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):
  self.inhibit_autoret=True;self.state.globals[self.key]=claripy.Concat(self.state.regs.h,self.state.regs.l);self.state.memory.store(TEXTBOX,claripy.BVV(1,8));self.state.regs.b=0xc4;self.state.regs.c=0xb9;self.jump(self.n)
class PostA(angr.SimProcedure):
 def __init__(self,key,post,n):super().__init__();self.key=key;self.post=post;self.n=n
 def run(self):
  self.inhibit_autoret=True;r=assembly_registers(self.state);self.state.globals[self.key]=claripy.Concat(*(r[x] for x in REGISTERS));setregs(self.state,self.post);self.jump(self.n)
class PredefA(angr.SimProcedure):
 def __init__(self,post):super().__init__();self.post=post
 def run(self):
  self.inhibit_autoret=True;s=self.state;entry=assembly_registers(s);bank=s.memory.load(LOADED,1);f=entry['f'];s.globals['dexcall']=claripy.Concat(*(entry[x] for x in REGISTERS));
  for a,v in zip(PREDEF,(claripy.BVV(0x56,8),entry['h'],entry['l'],entry['d'],entry['e'],entry['b'],entry['c'],bank,claripy.BVV(0x11,8))):s.memory.store(a,v)
  setregs(s,self.post[:8]);s.regs.a=bank;s.regs.f=sm83_flags_to_z80(f);s.memory.store(LOADED,bank);s.memory.store(ROMB,bank);s.globals['dexfields']=self.post[8:];self.jump(0x5276)
class DoneA(angr.SimProcedure):
 def run(self):self.inhibit_autoret=True;self.state.regs.h=0x24;self.state.regs.l=0xd6;self.jump(DONE)
class CountN(angr.SimProcedure):
 def __init__(self,count):super().__init__();self.count=count
 def run(self,a,m):
  r=native_registers(self.state,a);self.state.globals['countcall']=claripy.Concat(*(r[x] for x in REGISTERS));out=(self.count,0xc0,0,self.count,0,0,0xd3,0x0a)
  for i,v in enumerate(out):self.state.memory.store(a+i,claripy.BVV(v,8));self.state.memory.store(a+8,claripy.BVV(self.count,8))
class IsN(angr.SimProcedure):
 def __init__(self,results):super().__init__();self.results=results
 def run(self,a,m):
  idx=self.state.globals.get('isidx',0);r=native_registers(self.state,a);self.state.globals[f'is{idx}']=claripy.Concat(*(r[x] for x in REGISTERS));p=self.results[idx];self.state.globals['isidx']=idx+1;q=claripy.BVV(1 if p else 0,8);self.state.memory.store(a,q);self.state.memory.store(a+1,claripy.BVV(0x20|(0x80 if not p else 0),8));self.state.memory.store(a+2,q)
class PrintN(angr.SimProcedure):
 def run(self,a,m):
  idx=self.state.globals.get('pidx',0);r=native_registers(self.state,a);self.state.globals[f'p{idx}']=claripy.Concat(r['h'],r['l']);self.state.globals['pidx']=idx+1;self.state.memory.store(NM+TEXTBOX,claripy.BVV(1,8));self.state.memory.store(a+2,claripy.BVV(0xc4,8));self.state.memory.store(a+3,claripy.BVV(0xb9,8))
class PostN(angr.SimProcedure):
 def __init__(self,key,post):super().__init__();self.key=key;self.post=post
 def run(self,a,m):
  r=native_registers(self.state,a);self.state.globals[self.key]=claripy.Concat(*(r[x] for x in REGISTERS))
  for i,v in enumerate(self.post):self.state.memory.store(a+i,v)
class DexN(angr.SimProcedure):
 def __init__(self,post):super().__init__();self.post=post
 def run(self,a,m):
  self.state.globals['dexcall']=self.state.memory.load(a,8);self.state.globals['dexfields']=self.post[8:]
  for i,v in enumerate(self.post):self.state.memory.store(a+i,v)
def vals(prefix):
 v=symbolic_registers(prefix);v['give']=[claripy.BVS(prefix+f'_g{i}',8) for i in range(8)];v['remove']=[claripy.BVS(prefix+f'_r{i}',8) for i in range(8)];v['dex']=[claripy.BVS(prefix+f'_d{i}',8) for i in range(25)]
 for arr in ('give','remove','dex'):v[arr][1]=claripy.Concat(claripy.BVS(prefix+'_'+arr+'f',4),claripy.BVV(0,4))
 return v
def setup(s,pallet,lab,route,status,base=0):
 for a in MEMORY:s.memory.store(base+a,claripy.BVV(0x33,8))
 s.memory.store(base+PALLET,claripy.BVV(pallet,8));s.memory.store(base+LAB,claripy.BVV(lab,8));s.memory.store(base+ROUTE,claripy.BVV(route,8));s.memory.store(base+STATUS,claripy.BVV(status,8));s.memory.store(base+LOADED,claripy.BVV(7,8));s.memory.store(base+ROMB,claripy.BVV(7,8))
def calls(s,items):
 z64=claripy.BVV(0,64);z16=claripy.BVV(0,16);names=('countcall','is0','is1','givecall','removecall','dexcall');return claripy.Concat(*(s.globals.get(x,z64) for x in names),*(s.globals.get(f'p{i}',z16) for i in range(2)))
def assembly(v,pallet,lab,route,status,count,items):
 p=angr.Project(rom_window(ROM,7),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':0x5249})
 for a,addr,bit,n in ((0x5249,PALLET,6,0x524e),(0x525f,LAB,5,0x5264),(0x5280,ROUTE,5,0x5285),(0x5287,LAB,5,0x528c),(0x5292,STATUS,3,0x5297)):p.hook(a,Sm83LoadAImmediate(addr,a+3),length=3);p.hook(a+3,BitA(bit,n),length=2)
 p.hook(0x528e,BitA(3,0x5290),length=2);p.hook(0x5250,LoadHL(0xd2f7,0x5253),length=3);p.hook(0x5255,CountA(count),length=3);p.hook(0x5258,Sm83LoadAImmediate(NUM,0x525b),length=3);p.hook(0x525b,Sm83CpImmediate(2,0x525d),length=2)
 for a,text in ((0x5266,0x531d),(0x5299,0x52f0),(0x52a1,0x52f5),(0x52b0,0x52fa),(0x52b8,0x52ff),(0x52c8,0x5309),(0x52df,0x530e),(0x52e7,0x5318)):p.hook(a,LoadHL(text,a+3),length=3)
 for a,n in ((0x5269,0x526c),(0x529c,0x529f),(0x52a4,0x52a7),(0x52b3,0x52b6),(0x52bb,0x52be),(0x52cb,0x52ce),(0x52e2,0x52e5),(0x52ea,0x52ed)):p.hook(a,PrintA('p0',n),length=3)
 p.hook(0x526e,Sm83StoreAImmediate(TEXTCTL,0x5271),length=3);p.hook(0x5273,PredefA(v['dex']),length=3)
 seq=list(items);p.hook(0x527b,IsA(bool(seq[0]) if seq else False,'is0',0x527e),length=3);p.hook(0x52ab,IsA(bool(seq[1]) if len(seq)>1 else False,'is1',0x52ae),length=3)
 p.hook(0x52be,PostA('removecall',v['remove'],0x52c1),length=3);p.hook(0x52c3,Sm83StoreAImmediate(SCRIPT,0x52c6),length=3);p.hook(0x52d0,LoadHL(LAB,0x52d3),length=3);p.hook(0x52d3,CheckAndSet(),length=4);p.hook(0x52d9,LoadBC(),length=3);p.hook(0x52dc,PostA('givecall',v['give'],0x52df),length=3);p.hook(0x52ed,DoneA(),length=3)
 s=p.factory.blank_state(addr=0x5249);set_assembly_registers(s,v);setup(s,pallet,lab,route,status);m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=1);assert not m.errored and len(m.found)==1;e=m.found[0];return [E(**assembly_registers(e),state=claripy.Concat(*(assembly_registers(e)[x] for x in REGISTERS),claripy.BVV(0,16),*(e.globals.get('dexfields',v['dex'][8:]))),memory=amem(e),calls=calls(e,items),constraints=tuple(e.solver.constraints))]
def native(v,pallet,lab,route,status,count,items):
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_oaks_lab_oak1_text');sy={x:p.loader.find_symbol(x) for x in ('port_count_set_bits','port_is_item_in_bag','port_print_text','port_give_item','port_oaks_lab_script_remove_parcel','port_display_dex_rating_private')};assert f and all(sy.values());p.hook(sy['port_count_set_bits'].rebased_addr,CountN(count));p.hook(sy['port_is_item_in_bag'].rebased_addr,IsN(items or (False,)));p.hook(sy['port_print_text'].rebased_addr,PrintN());p.hook(sy['port_give_item'].rebased_addr,PostN('givecall',v['give']));p.hook(sy['port_oaks_lab_script_remove_parcel'].rebased_addr,PostN('removecall',v['remove']));p.hook(sy['port_display_dex_rating_private'].rebased_addr,DexN(v['dex']));s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,pallet,lab,route,status,NM);m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1;e=m.deadended[0];return [E(**native_registers(e,NS),state=e.memory.load(NS,27),memory=nmem(e),calls=calls(e,items),constraints=tuple(e.solver.constraints))]
@pytest.mark.skipif(not ELF.exists(),reason='native')
@pytest.mark.skipif(not ROM.exists() or not SYMS.exists(),reason='rom')
@pytest.mark.parametrize('name,pallet,lab,route,status,count,items,text',SCENARIOS,ids=[x[0] for x in SCENARIOS])
def test_oaks_lab_oak1_text_pathwise_equivalence(name,pallet,lab,route,status,count,items,text):
 v=vals(name);assert linked_bytes(ROM,symbol_location(SYMS,'OaksLabOak1Text'),len(EXPECTED)+1)[1:]==EXPECTED
 a=assembly(v,pallet,lab,route,status,count,items);n=native(v,pallet,lab,route,status,count,items);assert_pathwise_equivalent(a,n,(*REGISTERS,'memory','calls'))
 assert int.from_bytes(claripy.Solver().eval(n[0].state,1)[0].to_bytes(27,'big')[8:10],'little')==text
