from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate,Sm83CpRegister,Sm83LoadAImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;CONTINUE=0xeffc;MATCH=0xeffd;TERMINATOR=0xeffe;BOUNDARY=0xefff
NAMES=("wCurMap","wLastMap","wLastBlackoutMap")
class Bound(angr.SimProcedure):
 def __init__(self,target:int)->None:super().__init__();self.target=target
 def run(self)->None:self.jump(self.target)  # type: ignore[override]
class Start(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:  # type: ignore[override]
  if self.state.globals.get("entered",False):self.jump(CONTINUE);return
  self.state.globals["entered"]=True;self.state.regs.a=self.state.globals["fetched"];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def mem(x:angr.SimState,a:tuple[int,...],fetched:claripy.ast.BV)->claripy.ast.BV:return claripy.Concat(*(x.memory.load(v,1) for v in a),fetched)
def native(sym:str,i:dict[str,claripy.ast.BV],ret:bool=False)->list[E]:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for n,key in enumerate(("current","last","blackout","fetched"),8):s.memory.store(NATIVE_STATE+n,i[key])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,4),result=(x.regs.rax[7:0] if ret else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
def begin(i:dict[str,claripy.ast.BV])->E:
 loc=symbol_location(SYMBOLS,"SetLastBlackoutMap");a=tuple(symbol_location(SYMBOLS,n).address for n in NAMES);p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address+1});p.hook(loc.address+4,Sm83LoadAImmediate(a[0],loc.address+7),length=3);p.hook(loc.address+8,Bound(BOUNDARY),length=1);s=p.factory.blank_state(addr=loc.address+1);set_assembly_registers(s,i)
 for n,v in enumerate(a):s.memory.store(v,i[("current","last","blackout")[n]])
 m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);x=m.found[0];return E(**assembly_registers(x),memory=mem(x,a,i["fetched"]),result=claripy.BVV(0,8),constraints=tuple(x.solver.constraints))
def step(i:dict[str,claripy.ast.BV])->list[E]:
 loc=symbol_location(SYMBOLS,"SetLastBlackoutMap");loop=loc.address+8;a=tuple(symbol_location(SYMBOLS,n).address for n in NAMES);p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loop});p.hook(loop,Start(loop+1),length=1);p.hook(loop+1,Sm83CpImmediate(0xff,loop+3),length=2);p.hook(loop+5,Sm83CpRegister("b",loop+6),length=1);p.hook(loop+16,Bound(MATCH),length=1);p.hook(loop+10,Bound(TERMINATOR),length=1);s=p.factory.blank_state(addr=loop);set_assembly_registers(s,i);s.globals["fetched"]=i["fetched"]
 for n,v in enumerate(a):s.memory.store(v,i[("current","last","blackout")[n]])
 m=p.factory.simulation_manager(s);m.stashes["found"]=[]
 while m.active:
  m.move(from_stash="active",to_stash="found",filter_func=lambda x:x.addr in {CONTINUE,MATCH,TERMINATOR})
  if m.active:m.step()
 code={CONTINUE:0,MATCH:1,TERMINATOR:2};return [E(**assembly_registers(x),memory=mem(x,a,i["fetched"]),result=claripy.BVV(code[x.addr],8),constraints=tuple(x.solver.constraints)) for x in m.found]
def not_rest(i:dict[str,claripy.ast.BV])->E:
 loc=symbol_location(SYMBOLS,"SetLastBlackoutMap");start=loc.address+18;a=tuple(symbol_location(SYMBOLS,n).address for n in NAMES);p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":start});p.hook(start,Sm83LoadAImmediate(a[1],start+3),length=3);p.hook(start+3,Sm83StoreAImmediate(a[2],BOUNDARY),length=3);s=p.factory.blank_state(addr=start);set_assembly_registers(s,i)
 for n,v in enumerate(a):s.memory.store(v,i[("current","last","blackout")[n]])
 m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);x=m.found[0];return E(**assembly_registers(x),memory=mem(x,a,i["fetched"]),result=claripy.BVV(0,8),constraints=tuple(x.solver.constraints))
def inputs(prefix:str)->dict[str,claripy.ast.BV]:
 i=symbolic_registers(prefix)
 for key in ("current","last","blackout","fetched"):i[key]=claripy.BVS(prefix+"_"+key,8)
 return i
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_begin()->None:
 i=inputs("blackout_begin");assert_pathwise_equivalent([begin(i)],native("port_set_last_blackout_map_begin",i),(*REGISTERS,"memory"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_step()->None:
 i=inputs("blackout_step");assert_pathwise_equivalent(step(i),native("port_set_last_blackout_map_step",i,True),(*REGISTERS,"memory","result"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_not_resthouse()->None:
 i=inputs("blackout_finish");assert_pathwise_equivalent([not_rest(i)],native("port_set_last_blackout_map_not_resthouse",i),(*REGISTERS,"memory"))
def test_body()->None:
 loc=symbol_location(SYMBOLS,"SetLastBlackoutMap");assert linked_bytes(ROM,loc,26)==bytes.fromhex("e5219270fa5ed3472afeff2805b820f81806fa65d3ea19d7e1c9")
