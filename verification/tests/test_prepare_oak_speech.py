from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83LoadAImmediate,Sm83StoreAImmediate,Sm83XorA
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;STACK=0xd000;RETURN=0xffff
LPF=0xd358;OPT=0xd355;ST6=0xd732;OINIT=0xd08a;PN=0xd158;PNLEN=0xd8a;SPR=0xc100;SPRLEN=0x200
EXPECTED=bytes.fromhex('fa58d3f5fa55d3f5fa32d7f52158d1018a0dafcde0362100c1010002afcde036f1ea32d7f1ea55d3f1ea58d3fa8ad0a7ccff5b21aa451158d1010b00cdb50021b145114ad3010b00c3b500')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;hl:claripy.ast.BV
 lpdf:claripy.ast.BV;opt:claripy.ast.BV;st6:claripy.ast.BV;oinit:claripy.ast.BV
 names:claripy.ast.BV;sprites:claripy.ast.BV;fills:claripy.ast.BV
 constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 v=symbolic_registers(p)
 for name,addr in (('lpdf',LPF),('opt',OPT),('st6',ST6),('oinit',OINIT)):v[name]=claripy.BVS(f'{p}_{name}',8)
 return v
NAMES=b'NINTENPSONY@NINTENP'
def setup(s,v,native:bool):
 o=NM if native else 0
 for name,addr in (('lpdf',LPF),('opt',OPT),('st6',ST6),('oinit',OINIT)):s.memory.store(o+addr,v[name])

 s.memory.store(o+0x45aa,claripy.BVV(NAMES,8*len(NAMES)))
class Sm83XorA(angr.SimProcedure):
 """SM83 `XOR A` (AF): A := 0, Z set, N/H/C clear."""
 def __init__(self,next_address:int)->None:
  super().__init__();self._next=next_address
 def run(self):
  self.state.regs.a=claripy.BVV(0,8);self.state.regs.f=claripy.BVV(0x40,8);self.jump(self._next)
class FillMemorySite(angr.SimProcedure):
 """Proven FillMemory composition boundary at the call site: the fill
 byte, pointer, and count are concrete; the region is filled in one store,
 D/E are restored from the callee's saved copies, and the registers take
 the proven loop-exit state (A := fill byte, BC := 0, HL := end, F := Z)."""
 def __init__(self,next_address:int)->None:
  super().__init__();self._next=next_address
 def run(self):
  hl=self.state.solver.eval(self.state.regs.hl)
  bc=self.state.solver.eval(self.state.regs.bc)
  fill=self.state.solver.eval(self.state.regs.a)
  d=self.state.regs.d;e=self.state.regs.e
  if bc:self.state.memory.store(hl,claripy.BVV(fill,8*bc))
  self.state.regs.hl=hl+bc;self.state.regs.bc=claripy.BVV(0,16)
  self.state.regs.a=claripy.BVV(fill,8);self.state.regs.d=d;self.state.regs.e=e
  self.state.regs.f=claripy.BVV(0x40,8)
  self.jump(self._next)
class CopyDataSite(angr.SimProcedure):
 """Proven CopyData composition boundary at the call site: BC bytes are
 copied from [HL] to [DE] (concrete debug-name bytes), and the loop-exit
 registers take the proven state (A := last byte, BC := 0, HL/DE advanced,
 F := Z from `or b` with B == 0)."""
 def __init__(self,next_address:int)->None:
  super().__init__();self._next=next_address
 def run(self):
  hl=self.state.solver.eval(self.state.regs.hl)
  de=self.state.solver.eval(self.state.regs.de)
  bc=self.state.solver.eval(self.state.regs.bc)
  if bc:
   data=self.state.memory.load(hl,bc)
   self.state.memory.store(de,data)
   last=self.state.solver.eval(self.state.memory.load(de+bc-1,1))
  else:
   last=self.state.solver.eval(self.state.regs.a)
  self.state.regs.a=claripy.BVV(last,8)
  self.state.regs.hl=claripy.BVV(hl+bc,16)
  self.state.regs.de=claripy.BVV(de+bc,16)
  self.state.regs.bc=claripy.BVV(0,16)
  self.state.regs.f=claripy.BVV(0x40,8)
  self.jump(self._next)
class CopyDataTail(angr.SimProcedure):
 """The tail `jp CopyData`: the callee's RET pops the caller's sentinel."""
 def __init__(self,return_address:int)->None:
  super().__init__();self._ret=return_address
 def run(self):
  hl=self.state.solver.eval(self.state.regs.hl)
  de=self.state.solver.eval(self.state.regs.de)
  bc=self.state.solver.eval(self.state.regs.bc)
  if bc:
   data=self.state.memory.load(hl,bc)
   self.state.memory.store(de,data)
   last=self.state.solver.eval(self.state.memory.load(de+bc-1,1))
  else:
   last=self.state.solver.eval(self.state.regs.a)
  self.state.regs.a=claripy.BVV(last,8)
  self.state.regs.hl=claripy.BVV(hl+bc,16)
  self.state.regs.de=claripy.BVV(de+bc,16)
  self.state.regs.bc=claripy.BVV(0,16)
  self.state.regs.f=claripy.BVV(0x40,8)
  self.jump(self._ret)
def assembly(v):
 l=symbol_location(SYMS,'PrepareOakSpeech')
 assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+0,Sm83LoadAImmediate(LPF,b+3),length=3)          # ld a,[wLetterPrintingDelayFlags]
 p.hook(b+4,Sm83LoadAImmediate(OPT,b+7),length=3)          # ld a,[wOptions]
 p.hook(b+8,Sm83LoadAImmediate(ST6,b+11),length=3)         # ld a,[wStatusFlags6]
 p.hook(b+18,Sm83XorA(b+19),length=1)                      # xor a
 p.hook(b+19,FillMemorySite(b+22),length=3)                # call FillMemory
 p.hook(b+28,Sm83XorA(b+29),length=1)                      # xor a
 p.hook(b+29,FillMemorySite(b+32),length=3)                # call FillMemory
 p.hook(b+44,Sm83LoadAImmediate(OINIT,b+47),length=3)      # ld a,[wOptionsInitialized]
 p.hook(b+33,Sm83StoreAImmediate(ST6,b+36),length=3)       # ld [wStatusFlags6],a
 p.hook(b+37,Sm83StoreAImmediate(OPT,b+40),length=3)       # ld [wOptions],a
 p.hook(b+41,Sm83StoreAImmediate(LPF,b+44),length=3)       # ld [wLetterPrintingDelayFlags],a
 p.hook(b+60,CopyDataSite(b+63),length=3)                  # call CopyData (player name)
 io=symbol_location(SYMS,'InitOptions')
 assert io.bank==l.bank,f'InitOptions must be in the same bank: {io.bank}/{l.bank}'
 assert linked_bytes(ROM,io,11)==bytes.fromhex('3e01ea58d33e03ea55d3c9')
 p.hook(io.address+2,Sm83StoreAImmediate(LPF,io.address+5),length=3)   # ld [wLetterPrintingDelayFlags],a
 p.hook(io.address+7,Sm83StoreAImmediate(OPT,io.address+10),length=3)  # ld [wOptions],a
 p.hook(b+72,CopyDataTail(RETURN),length=3)                # jp CopyData tail: its RET pops the sentinel
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);setup(s,v,False);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(s);m.explore(find=lambda st:st.addr==RETURN,num_find=64);assert not m.errored and len(m.found)==2
 out=[]
 for x in m.found:
  ar=assembly_registers(x)
  out.append(E(**{**{k:v for k,v in ar.items() if k not in ('h','l')},'hl':x.regs.hl},lpdf=x.memory.load(LPF,1),opt=x.memory.load(OPT,1),st6=x.memory.load(ST6,1),oinit=x.memory.load(OINIT,1),names=claripy.Concat(*(x.memory.load(PN+i,1) for i in range(11))),sprites=claripy.Concat(x.memory.load(SPR,1),x.memory.load(SPR+1,1),x.memory.load(SPR+SPRLEN-2,1),x.memory.load(SPR+SPRLEN-1,1)),fills=claripy.Concat(x.memory.load(PN+11,1),x.memory.load(PN+PNLEN-1,1),x.memory.load(SPR+2,1),x.memory.load(SPR+SPRLEN-3,1)),constraints=tuple(x.solver.constraints)))
 return out
def native(v):
 p=angr.Project(ELF,auto_load_libs=False)
 f=p.loader.find_symbol('port_prepare_oak_speech');assert f
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v,True)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==2
 out=[]
 for x in m.deadended:
  nr=native_registers(x,NS)
  out.append(E(**{**{k:v for k,v in nr.items() if k not in ('h','l')},'hl':claripy.Concat(nr['h'],nr['l'])},lpdf=x.memory.load(NM+LPF,1),opt=x.memory.load(NM+OPT,1),st6=x.memory.load(NM+ST6,1),oinit=x.memory.load(NM+OINIT,1),names=claripy.Concat(*(x.memory.load(NM+PN+i,1) for i in range(11))),sprites=claripy.Concat(x.memory.load(NM+SPR,1),x.memory.load(NM+SPR+1,1),x.memory.load(NM+SPR+SPRLEN-2,1),x.memory.load(NM+SPR+SPRLEN-1,1)),fills=claripy.Concat(x.memory.load(NM+PN+11,1),x.memory.load(NM+PN+PNLEN-1,1),x.memory.load(NM+SPR+2,1),x.memory.load(NM+SPR+SPRLEN-3,1)),constraints=tuple(x.solver.constraints)))
 return out
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_prepare_oak_speech_pathwise_equivalence():
 v=inputs('prepare_oak_speech');_ea=assembly(v);_en=native(v);assert_pathwise_equivalent(_ea,_en,('a','f','b','c','d','e','hl','lpdf','opt','st6','oinit','names','sprites','fills'))
