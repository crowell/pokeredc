from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83CpRegister,Sm83DecRegister,Sm83LoadAImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;STACK=0xd000;GB_RETURN=0xffff;LOOP=0xeffd;FINISH=0xeffe;BOUNDARY=0xefff
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;value:claripy.ast.BV;fetched:claripy.ast.BV;cont:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class Bound(angr.SimProcedure):
 def __init__(self,target:int)->None:super().__init__();self.target=target
 def run(self)->None:self.jump(self.target)  # type: ignore[override]
class StepStart(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:  # type: ignore[override]
  if self.state.globals.get("entered",False):self.jump(LOOP);return
  self.state.globals["entered"]=True;old=self.state.regs.c;result=old+1;flags=self.state.regs.f&1;flags|=claripy.If(result==0,claripy.BVV(0x40,8),claripy.BVV(0,8));flags|=claripy.If((old&0xf)==0xf,claripy.BVV(0x10,8),claripy.BVV(0,8));self.state.regs.c=result;self.state.regs.f=flags;self.jump(self.n)
class FetchHli(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:self.state.regs.a=self.state.globals["fetched"];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
class LoadComputed(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:self.state.regs.a=self.state.globals["fetched"];self.jump(self.n)  # type: ignore[override]
def endpoint(x:angr.SimState,value:claripy.ast.BV,fetched:claripy.ast.BV,cont:int|claripy.ast.BV)->E:
 return E(**assembly_registers(x),value=value,fetched=fetched,cont=claripy.BVV(cont,8) if isinstance(cont,int) else cont,constraints=tuple(x.solver.constraints))
def native(sym:str,i:dict[str,claripy.ast.BV],ret:bool=False,args:tuple[claripy.ast.BV,...]=())->list[E]:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE,*args);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i["value"]);s.memory.store(NATIVE_STATE+9,i["fetched"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),value=x.memory.load(NATIVE_STATE+8,1),fetched=x.memory.load(NATIVE_STATE+9,1),cont=(claripy.If(x.regs.rax[7:0]==0,claripy.BVV(1,8),claripy.BVV(0,8)) if ret else claripy.BVV(1,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
def begin(i:dict[str,claripy.ast.BV])->E:
 loc=symbol_location(SYMBOLS,"PokedexToIndex");value=symbol_location(SYMBOLS,"wPokedexNum").address;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address+2});p.hook(loc.address+2,Sm83LoadAImmediate(value,loc.address+5),length=3);p.hook(loc.address+11,Bound(BOUNDARY),length=1);s=p.factory.blank_state(addr=loc.address+2);set_assembly_registers(s,i);s.memory.store(value,i["value"]);m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);x=m.found[0];return endpoint(x,x.memory.load(value,1),i["fetched"],1)
def step(i:dict[str,claripy.ast.BV])->list[E]:
 loc=symbol_location(SYMBOLS,"PokedexToIndex");loop=loc.address+11;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loop});p.hook(loop,StepStart(loop+1),length=1);p.hook(loop+1,FetchHli(loop+2),length=1);p.hook(loop+2,Sm83CpRegister("b",loop+3),length=1);p.hook(loop+5,Bound(FINISH),length=1);s=p.factory.blank_state(addr=loop);set_assembly_registers(s,i);s.globals["fetched"]=i["fetched"];m=p.factory.simulation_manager(s);m.stashes["found"]=[]
 while m.active:
  m.move(from_stash="active",to_stash="found",filter_func=lambda x:x.addr in {LOOP,FINISH})
  if m.active:m.step()
 return [endpoint(x,i["value"],i["fetched"],1 if x.addr==LOOP else 0) for x in m.found]
def finish(i:dict[str,claripy.ast.BV])->E:
 loc=symbol_location(SYMBOLS,"PokedexToIndex");value=symbol_location(SYMBOLS,"wPokedexNum").address;start=loc.address+16;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":start});p.hook(start+1,Sm83StoreAImmediate(value,BOUNDARY),length=3);s=p.factory.blank_state(addr=start);set_assembly_registers(s,i);s.memory.store(value,i["value"]);m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);x=m.found[0];return endpoint(x,x.memory.load(value,1),i["fetched"],1)
def index_assembly(i:dict[str,claripy.ast.BV])->E:
 loc=symbol_location(SYMBOLS,"IndexToPokedex");value=symbol_location(SYMBOLS,"wPokedexNum").address;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address+2,Sm83LoadAImmediate(value,loc.address+5),length=3);p.hook(loc.address+5,Sm83DecRegister("a",loc.address+6),length=1);p.hook(loc.address+12,Sm83AddHlRegisterPair("bc",loc.address+13),length=1);p.hook(loc.address+13,LoadComputed(loc.address+14),length=1);p.hook(loc.address+14,Sm83StoreAImmediate(value,loc.address+17),length=3);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.memory.store(value,i["value"]);s.globals["fetched"]=i["fetched"];s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(GB_RETURN,16),endness="Iend_LE");ends=collect_returns(p,s,GB_RETURN);assert len(ends)==1;x=ends[0];return endpoint(x,x.memory.load(value,1),i["fetched"],1)
def inputs(prefix:str)->dict[str,claripy.ast.BV]:
 i=symbolic_registers(prefix);i["value"]=claripy.BVS(prefix+"_value",8);i["fetched"]=claripy.BVS(prefix+"_fetched",8);return i
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_pokedex_to_index_begin()->None:
 i=inputs("dex_to_index_begin");assert_pathwise_equivalent([begin(i)],native("port_pokedex_to_index_begin",i),(*REGISTERS,"value","fetched","cont"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_pokedex_to_index_step()->None:
 i=inputs("dex_to_index_step");assert_pathwise_equivalent(step(i),native("port_pokedex_to_index_step",i,True),(*REGISTERS,"value","fetched","cont"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_pokedex_to_index_finish()->None:
 i=inputs("dex_to_index_finish");assert_pathwise_equivalent([finish(i)],native("port_pokedex_to_index_finish",i),(*REGISTERS,"value","fetched","cont"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_index_to_pokedex()->None:
 i=inputs("index_to_dex");assert_pathwise_equivalent([index_assembly(i)],native("port_index_to_pokedex",i),(*REGISTERS,"value","fetched","cont"))
def test_bodies()->None:
 for symbol,body in (("PokedexToIndex","c5e5fa1ed1470e002124500c2ab820fb79ea1ed1e1c1c9"),("IndexToPokedex","c5e5fa1ed13d21245006004f097eea1ed1e1c1c9")):
  expected=bytes.fromhex(body);assert linked_bytes(ROM,symbol_location(SYMBOLS,symbol),len(expected))==expected
