from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate,Sm83LoadAAtHlIncrement,Sm83LoadAImmediate,Sm83StoreAImmediate,Sm83XorA
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;STACK=0xd000;RETURN=0xffff
FLAGS=0xd5a6;FLAGSEND=0xd5c6;COUNTER=0xd048;TABLE=0x4aea;TABLE_LEN=687
EXPECTED=bytes.fromhex('21a6d5012000afcde03621ea4aafea48d02afeffc8e5237efe11200c21a6d5fa48d04f0601cde6712148d034e1232318e0f0')
TABLE_EXPECTED='000111010515010711020315020515030111030215030611030a15030b150a01150a02150a03150a04150a05150a06150a07150a08110a09110a0a110a0b110a0c110a0d110a0e150a0f110d01150d02150f0315140a15170115170915170a151a0b151b0715210111210211230115230815240a152701152702112703152801152802152803152804152805112806152807152808112d01152d0b15340515e40115e40215e403158f0115900415910415910515910615920615930415930515940115940215940315940415950511840215870b159b0215a50215a50315b10615b10715b50111530115530215530315530415530515530615530715530815530915530a15530b15530c15530d15530e15c20615c20715c20815c20915c20a15c20d155801155802115803113305153306153307153b08153b09153b0a153b0b153b0c153b0d153d06153d07153d08153d0915600211660a15670615670915680915680a15680b15c60515c60615c60a15c70615c70715c80215c80315c80415c80515c90315c90415ca0115ca0515ca0615ca0715ca0811ca0911cf0115cf0215cf0315cf0415cf0515d00215d00315d00415d10215d10315d10415d10515d10615d10715d20215d20315d20415d20515d20615d20715d20815d30615d30715d30815d30915d30a15d40515d40615d40715d40815d40915d40a15d40b15d40c15d50215d50315d50415e90215e90315e90415ea0115ea0215ea0315ea0415ea0515ea0615eb0315eb0415eb0515f40215d60215d70315d70415d80315d80415d80515d80615d80815d90115d90215d90315d90415da0115da0215db0115db0215db0315db0415dc0115e20115e20215e20315e30115e30215e303156c03156c0415780211c00115c002159f01119f0211a00111a00211a10215a10315a10511a10611a20111a20211a20315ff0115'
TABLE_EXPECTED=bytes.fromhex(TABLE_EXPECTED)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;hl:claripy.ast.BV
 flags:claripy.ast.BV;counter:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 v=symbolic_registers(p);v['flags_in']=claripy.BVS(f'{p}_flags_in',8*0x20);v['counter_in']=claripy.BVS(f'{p}_counter_in',8)
 return v
def setup(s,v,native:bool):
 o=NM if native else 0
 s.memory.store(o+FLAGS,v['flags_in']);s.memory.store(o+COUNTER,v['counter_in'])
 if not native:s.memory.store(TABLE,claripy.BVV(TABLE_EXPECTED,8*TABLE_LEN))
class FillMemorySite(angr.SimProcedure):
 """Proven FillMemory composition boundary at the call site: the fill
 byte, pointer, and count are concrete; the region is filled in one store,
 D/E are restored from the callee's saved copies, and the registers take
 the proven loop-exit state (A := fill byte, BC := 0, HL := end, F := Z)."""
 def __init__(self,next_address:int)->None:
  super().__init__();self._next=next_address
 def run(self):
  hl=self.state.solver.eval(self.state.regs.hl);bc=self.state.solver.eval(self.state.regs.bc);fill=self.state.solver.eval(self.state.regs.a)
  d=self.state.regs.d;e=self.state.regs.e
  if bc:self.state.memory.store(hl,claripy.BVV(fill,8*bc))
  self.state.regs.hl=hl+bc;self.state.regs.bc=claripy.BVV(0,16);self.state.regs.a=claripy.BVV(fill,8);self.state.regs.d=d;self.state.regs.e=e;self.state.regs.f=claripy.BVV(0x40,8)
  self.jump(self._next)
class FlagActionSetSite(angr.SimProcedure):
 """Proven ToggleableObjectFlagAction composition boundary at the call
 site: B == FLAG_SET (1), C == the global flag index, HL ==
 wToggleableObjectFlags. The proven transition sets bit C&7 of the flag
 byte at HL+C/8, returns the result in A and C with F := Z from the OR,
 and preserves B/D/E/H/L (the callee's pushes/pops are balanced)."""
 def __init__(self,next_address:int)->None:
  super().__init__();self._next=next_address
 def run(self):
  c=self.state.solver.eval(self.state.regs.c);hl=self.state.solver.eval(self.state.regs.hl)
  addr=hl+(c>>3);byte=self.state.solver.eval(self.state.memory.load(addr,1));result=byte|(1<<(c&7))
  self.state.memory.store(addr,claripy.BVV(result,8))
  self.state.regs.a=claripy.BVV(result,8);self.state.regs.c=claripy.BVV(result,8);self.state.regs.f=claripy.BVV(0x40 if result==0 else 0,8)
  self.jump(self._next)
def assembly(v):
 l=symbol_location(SYMS,'InitializeToggleableObjectsFlags');t=symbol_location(SYMS,'ToggleableObjectStates');g=symbol_location(SYMS,'ToggleableObjectFlagAction')
 assert l.bank==t.bank==g.bank,f'body/table/callee must share a bank: {l.bank}/{t.bank}/{g.bank}'
 assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 assert linked_bytes(ROM,t,TABLE_LEN)==TABLE_EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+6,Sm83XorA(b+7),length=1)                          # xor a (fill byte)
 p.hook(b+7,FillMemorySite(b+10),length=3)                   # call FillMemory
 p.hook(b+13,Sm83XorA(b+14),length=1)                        # xor a (counter = 0)
 p.hook(b+14,Sm83StoreAImmediate(COUNTER,b+17),length=3)     # ld [wToggleableObjectCounter],a
 p.hook(b+17,Sm83LoadAAtHlIncrement(b+18),length=1)          # ld a,[hli]
 p.hook(b+18,Sm83CpImmediate(0xff,b+20),length=2)            # cp -1
 p.hook(b+24,Sm83CpImmediate(0x11,b+26),length=2)            # cp OFF
 p.hook(b+31,Sm83LoadAImmediate(COUNTER,b+34),length=3)      # ld a,[wToggleableObjectCounter]
 p.hook(b+37,FlagActionSetSite(b+40),length=3)               # call ToggleableObjectFlagAction
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v,False);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(s);m.explore(find=lambda st:st.addr==RETURN,num_find=64);assert not m.errored and len(m.found)==1
 out=[]
 for x in m.found:
  ar=assembly_registers(x)
  out.append(E(**{**{k:v for k,v in ar.items() if k not in ('h','l')},'hl':x.regs.hl},flags=claripy.Concat(*(x.memory.load(FLAGS+i,1) for i in range(0x20))),counter=x.memory.load(COUNTER,1),constraints=tuple(x.solver.constraints)))
 return out
def native(v):
 p=angr.Project(ELF,auto_load_libs=False)
 f=p.loader.find_symbol('port_initialize_toggleable_objects_flags');assert f
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v,True)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1
 out=[]
 for x in m.deadended:
  nr=native_registers(x,NS)
  out.append(E(**{**{k:v for k,v in nr.items() if k not in ('h','l')},'hl':claripy.Concat(nr['h'],nr['l'])},flags=claripy.Concat(*(x.memory.load(NM+FLAGS+i,1) for i in range(0x20))),counter=x.memory.load(NM+COUNTER,1),constraints=tuple(x.solver.constraints)))
 return out
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_initialize_toggleable_objects_flags_pathwise_equivalence():
 v=inputs('itof');assert_pathwise_equivalent(assembly(v),native(v),('a','f','b','c','d','e','hl','flags','counter'))
