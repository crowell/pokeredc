from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83CpRegister,Sm83LoadAImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;CONTINUE=0xeffd;MATCH=0xeffe;BOUNDARY=0xefff
class Bound(angr.SimProcedure):
 def __init__(self,target:int)->None:super().__init__();self.target=target
 def run(self)->None:self.jump(self.target)  # type: ignore[override]
class FetchStep(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:  # type: ignore[override]
  if self.state.globals.get("entered",False):self.jump(CONTINUE);return
  self.state.globals["entered"]=True;self.state.regs.a=self.state.globals["fetched_species"];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
class FetchLevel(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:self.state.regs.a=self.state.globals["fetched_level"];self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def memory(x:angr.SimState,species:int,enemy:int,i:dict[str,claripy.ast.BV])->claripy.ast.BV:return claripy.Concat(x.memory.load(species,1),x.memory.load(enemy,1),i["fetched_species"],i["fetched_level"])
def native(sym:str,i:dict[str,claripy.ast.BV],ret:bool=False)->list[E]:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for n,key in enumerate(("species","enemy","fetched_species","fetched_level")):s.memory.store(NATIVE_STATE+8+n,i[key])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=claripy.Concat(*(x.memory.load(NATIVE_STATE+8+n,1) for n in range(4))),result=(x.regs.rax[7:0] if ret else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
def project(loc):return angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address})
def begin(i:dict[str,claripy.ast.BV])->E:
 loc=symbol_location(SYMBOLS,"GetPrizeMonLevel");species=symbol_location(SYMBOLS,"wCurPartySpecies").address;enemy=symbol_location(SYMBOLS,"wCurEnemyLevel").address;p=project(loc);p.hook(loc.address,Sm83LoadAImmediate(species,loc.address+3),length=3);p.hook(loc.address+7,Bound(BOUNDARY),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.memory.store(species,i["species"]);s.memory.store(enemy,i["enemy"]);m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);x=m.found[0];return E(**assembly_registers(x),memory=memory(x,species,enemy,i),result=claripy.BVV(0,8),constraints=tuple(x.solver.constraints))
def step(i:dict[str,claripy.ast.BV])->list[E]:
 loc=symbol_location(SYMBOLS,"GetPrizeMonLevel");loop=loc.address+7;species=symbol_location(SYMBOLS,"wCurPartySpecies").address;enemy=symbol_location(SYMBOLS,"wCurEnemyLevel").address;p=project(loc);p.hook(loop,FetchStep(loop+1),length=1);p.hook(loop+1,Sm83CpRegister("b",loop+2),length=1);p.hook(loop+7,Bound(MATCH),length=1);s=p.factory.blank_state(addr=loop);set_assembly_registers(s,i);s.memory.store(species,i["species"]);s.memory.store(enemy,i["enemy"]);s.globals["fetched_species"]=i["fetched_species"];m=p.factory.simulation_manager(s);m.stashes["found"]=[]
 while m.active:
  m.move(from_stash="active",to_stash="found",filter_func=lambda x:x.addr in {CONTINUE,MATCH})
  if m.active:m.step()
 return [E(**assembly_registers(x),memory=memory(x,species,enemy,i),result=claripy.BVV(1 if x.addr==MATCH else 0,8),constraints=tuple(x.solver.constraints)) for x in m.found]
def finish(i:dict[str,claripy.ast.BV])->E:
 loc=symbol_location(SYMBOLS,"GetPrizeMonLevel");start=loc.address+14;species=symbol_location(SYMBOLS,"wCurPartySpecies").address;enemy=symbol_location(SYMBOLS,"wCurEnemyLevel").address;p=project(loc);p.hook(start,FetchLevel(start+1),length=1);p.hook(start+1,Sm83StoreAImmediate(enemy,BOUNDARY),length=3);s=p.factory.blank_state(addr=start);set_assembly_registers(s,i);s.memory.store(species,i["species"]);s.memory.store(enemy,i["enemy"]);s.globals["fetched_level"]=i["fetched_level"];m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);x=m.found[0];return E(**assembly_registers(x),memory=memory(x,species,enemy,i),result=claripy.BVV(0,8),constraints=tuple(x.solver.constraints))
def inputs(prefix:str)->dict[str,claripy.ast.BV]:
 i=symbolic_registers(prefix)
 for key in ("species","enemy","fetched_species","fetched_level"):i[key]=claripy.BVS(prefix+"_"+key,8)
 return i
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_begin()->None:
 i=inputs("prize_level_begin");assert_pathwise_equivalent([begin(i)],native("port_get_prize_mon_level_begin",i),(*REGISTERS,"memory"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_step()->None:
 i=inputs("prize_level_step");assert_pathwise_equivalent(step(i),native("port_get_prize_mon_level_step",i,True),(*REGISTERS,"memory","result"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_finish()->None:
 i=inputs("prize_level_finish");assert_pathwise_equivalent([finish(i)],native("port_get_prize_mon_level_finish",i),(*REGISTERS,"memory"))
def test_body()->None:
 loc=symbol_location(SYMBOLS,"GetPrizeMonLevel");assert linked_bytes(ROM,loc,19)==bytes.fromhex("fa91cf47218a692ab828032318f97eea27d1c9")
