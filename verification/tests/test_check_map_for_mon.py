from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83DecRegister,Sm83LoadAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;CONTINUE=0xeffe;DONE=0xefff
class Bound(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)  # type: ignore[override]
class Load(angr.SimProcedure):
 def __init__(self,n,address):super().__init__();self.n=n;self.address=address
 def run(self):  # type: ignore[override]
  if self.state.globals.get("entered",False):self.jump(CONTINUE);return
  self.state.globals["entered"]=True;self.state.globals["matched"]=claripy.BVV(0,8);self.state.regs.a=self.state.memory.load(self.address,1);self.jump(self.n)
class CpFetched(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):  # type: ignore[override]
  left=self.state.regs.a;right=self.state.globals["fetched"];flags=claripy.BVV(2,8)|claripy.If(left==right,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If((left&0xf).ULT(right&0xf),claripy.BVV(0x10,8),claripy.BVV(0,8))|claripy.If(left.ULT(right),claripy.BVV(1,8),claripy.BVV(0,8));self.state.regs.f=flags;self.jump(self.n)
class Store(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals["written"]=self.state.regs.a;self.state.globals["matched"]=claripy.BVV(1,8);self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def memory(x,i):return claripy.Concat(x.memory.load(symbol_location(SYMBOLS,"wPokedexNum").address,1),i["fetched"],x.globals.get("written",i["written"]),x.globals.get("matched",i["matched"]))
def native(sym,i,ret=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for n,key in enumerate(("pokedex","fetched","written","matched")):s.memory.store(NATIVE_STATE+8+n,i[key])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=claripy.Concat(*(x.memory.load(NATIVE_STATE+8+n,1) for n in range(4))),result=(x.regs.rax[7:0] if ret else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
def project(loc):return angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address})
def begin(i):
 loc=symbol_location(SYMBOLS,"CheckMapForMon");p=project(loc);p.hook(loc.address+3,Bound(DONE),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.memory.store(symbol_location(SYMBOLS,"wPokedexNum").address,i["pokedex"]);m=p.factory.simulation_manager(s);m.explore(find=DONE);x=m.found[0];x.globals["written"]=i["written"];x.globals["matched"]=i["matched"];return E(**assembly_registers(x),memory=memory(x,i),result=claripy.BVV(0,8),constraints=tuple(x.solver.constraints))
def step(i):
 loc=symbol_location(SYMBOLS,"CheckMapForMon");loop=loc.address+3;p=project(loc);pokedex=symbol_location(SYMBOLS,"wPokedexNum").address;p.hook(loop,Load(loop+3,pokedex),length=3);p.hook(loop+3,CpFetched(loop+4),length=1);p.hook(loop+7,Store(loop+8),length=1);p.hook(loop+11,Sm83DecRegister("b",loop+12),length=1);p.hook(loop+14,Bound(DONE),length=1);s=p.factory.blank_state(addr=loop);set_assembly_registers(s,i);s.memory.store(pokedex,i["pokedex"]);s.globals["fetched"]=i["fetched"];s.globals["written"]=i["written"];s.globals["matched"]=i["matched"];m=p.factory.simulation_manager(s);m.stashes["found"]=[]
 while m.active:
  m.move(from_stash="active",to_stash="found",filter_func=lambda x:x.addr in {CONTINUE,DONE})
  if m.active:m.step()
 return [E(**assembly_registers(x),memory=memory(x,i),result=claripy.BVV(1 if x.addr==DONE else 0,8),constraints=tuple(x.solver.constraints)) for x in m.found]
def finish(i):
 loc=symbol_location(SYMBOLS,"CheckMapForMon");p=project(loc);p.hook(loc.address+18,Bound(DONE),length=1);s=p.factory.blank_state(addr=loc.address+17);set_assembly_registers(s,i);s.memory.store(symbol_location(SYMBOLS,"wPokedexNum").address,i["pokedex"]);s.globals["written"]=i["written"];s.globals["matched"]=i["matched"];m=p.factory.simulation_manager(s);m.explore(find=DONE);x=m.found[0];return E(**assembly_registers(x),memory=memory(x,i),result=claripy.BVV(0,8),constraints=tuple(x.solver.constraints))
def inputs(prefix):
 i=symbolic_registers(prefix)
 for key in ("pokedex","fetched","written","matched"):i[key]=claripy.BVS(prefix+"_"+key,8)
 return i
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_begin():
 i=inputs("map_mon_begin");assert_pathwise_equivalent([begin(i)],native("port_check_map_for_mon_begin",i),(*REGISTERS,"memory"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_step():
 i=inputs("map_mon_step");assert_pathwise_equivalent(step(i),native("port_check_map_for_mon_step",i,True),(*REGISTERS,"memory","result"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_finish():
 i=inputs("map_mon_finish");assert_pathwise_equivalent([finish(i)],native("port_check_map_for_mon_finish",i),(*REGISTERS,"memory"))
def test_body():
 loc=symbol_location(SYMBOLS,"CheckMapForMon");assert linked_bytes(ROM,loc,19)==bytes.fromhex("23060afa1ed1be200379121323230520f22bc9")
