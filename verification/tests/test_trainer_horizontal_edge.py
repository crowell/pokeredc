from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83DecRegister,Sm83LoadAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;LOOP=0xeffd;RETURN=0xeffe;BOUNDARY=0xefff
class StoreHli(angr.SimProcedure):
 def __init__(self,n:int,key:str,once:bool=False)->None:super().__init__();self.n=n;self.key=key;self.once=once
 def run(self)->None:  # type: ignore[override]
  if self.once and self.state.globals.get("entered",False):self.jump(LOOP);return
  if self.once:self.state.globals["entered"]=True
  self.state.globals[self.key]=self.state.regs.a;self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
class Store(angr.SimProcedure):
 def run(self)->None:self.state.globals["written"]=self.state.regs.a;self.jump(BOUNDARY)  # type: ignore[override]
class Bound(angr.SimProcedure):
 def run(self)->None:self.jump(BOUNDARY)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;written:claripy.ast.BV;cont:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def nend(sym:str,i:dict[str,claripy.ast.BV],args:tuple[claripy.ast.BV,...]=(),ret:bool=False)->list[E]:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE,*args);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i["written"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),written=x.memory.load(NATIVE_STATE+8,1),cont=(claripy.If(x.regs.rax[7:0]==0,claripy.BVV(1,8),claripy.BVV(0,8)) if ret else claripy.BVV(1,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
def begin(i:dict[str,claripy.ast.BV])->E:
 loc=symbol_location(SYMBOLS,"TrainerInfo_DrawHorizontalEdge");width=symbol_location(SYMBOLS,"wTrainerInfoTextBoxWidth").address;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address,StoreHli(loc.address+1,"written"),length=1);p.hook(loc.address+1,Sm83LoadAImmediate(width,loc.address+4),length=3);p.hook(loc.address+6,Bound(),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.memory.store(width,i["width"]);s.globals["written"]=i["written"];m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);x=m.found[0];return E(**assembly_registers(x),written=x.globals["written"],cont=claripy.BVV(1,8),constraints=tuple(x.solver.constraints))
def step(i:dict[str,claripy.ast.BV])->list[E]:
 loc=symbol_location(SYMBOLS,"TrainerInfo_DrawHorizontalEdge");loop=loc.address+6;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loop});p.hook(loop,StoreHli(loop+1,"written",True),length=1);p.hook(loop+1,Sm83DecRegister("c",loop+2),length=1);p.hook(loop+4,Bound(),length=1);s=p.factory.blank_state(addr=loop);set_assembly_registers(s,i);s.globals["written"]=i["written"];m=p.factory.simulation_manager(s);m.stashes["found"]=[]
 while m.active:
  m.move(from_stash="active",to_stash="found",filter_func=lambda x:x.addr in {LOOP,BOUNDARY})
  if m.active:m.step()
 return [E(**assembly_registers(x),written=x.globals["written"],cont=claripy.BVV(1 if x.addr==LOOP else 0,8),constraints=tuple(x.solver.constraints)) for x in m.found]
def finish(i:dict[str,claripy.ast.BV])->E:
 loc=symbol_location(SYMBOLS,"TrainerInfo_DrawHorizontalEdge");start=loc.address+10;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":start});p.hook(start+1,Store(),length=1);s=p.factory.blank_state(addr=start);set_assembly_registers(s,i);s.globals["written"]=i["written"];m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);x=m.found[0];return E(**assembly_registers(x),written=x.globals["written"],cont=claripy.BVV(1,8),constraints=tuple(x.solver.constraints))
def inputs(prefix:str)->dict[str,claripy.ast.BV]:
 i=symbolic_registers(prefix);i["written"]=claripy.BVS(prefix+"_written",8);i["width"]=claripy.BVS(prefix+"_width",8);return i
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_begin()->None:
 i=inputs("horizontal_begin");assert_pathwise_equivalent([begin(i)],nend("port_trainer_info_draw_horizontal_edge_begin",i,(claripy.ZeroExt(56,i["width"]),)),(*REGISTERS,"written","cont"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_step()->None:
 i=inputs("horizontal_step");assert_pathwise_equivalent(step(i),nend("port_trainer_info_draw_horizontal_edge_step",i,ret=True),(*REGISTERS,"written","cont"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_finish()->None:
 i=inputs("horizontal_finish");assert_pathwise_equivalent([finish(i)],nend("port_trainer_info_draw_horizontal_edge_finish",i),(*REGISTERS,"written","cont"))
def test_body()->None:
 loc=symbol_location(SYMBOLS,"TrainerInfo_DrawHorizontalEdge");assert linked_bytes(ROM,loc,13)==bytes.fromhex("22fa3ecd4f7a220d20fc7b77c9")
