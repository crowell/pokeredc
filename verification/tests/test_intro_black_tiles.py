from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83DecRegister
ROOT=Path(__file__).resolve().parents[2];VERIFY=ROOT/"verification";NATIVE_ELF=VERIFY/"build"/"ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;LOOP=0xeffe;RETURN=0xefff
class Store(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:  # type: ignore[override]
  if self.state.globals.get("entered",False):self.jump(LOOP);return
  self.state.globals["entered"]=True;self.state.globals["written"]=self.state.regs.a;self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
class Bound(angr.SimProcedure):
 def __init__(self,a:int)->None:super().__init__();self.a=a
 def run(self)->None:self.jump(self.a)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;written:claripy.ast.BV;cont:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def native(sym:str,i:dict[str,claripy.ast.BV],ret:bool)->list[E]:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i["written"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),written=x.memory.load(NATIVE_STATE+8,1),cont=(claripy.If(x.regs.rax[7:0]==0,claripy.BVV(1,8),claripy.BVV(0,8)) if ret else claripy.BVV(1,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
def begin(i:dict[str,claripy.ast.BV])->E:
 loc=symbol_location(SYMBOLS,"IntroPlaceBlackTiles");p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address+2,Bound(LOOP),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);m=p.factory.simulation_manager(s);m.explore(find=LOOP);x=m.found[0];return E(**assembly_registers(x),written=i["written"],cont=claripy.BVV(1,8),constraints=tuple(x.solver.constraints))
def step(i:dict[str,claripy.ast.BV])->list[E]:
 loc=symbol_location(SYMBOLS,"IntroPlaceBlackTiles");loop=loc.address+2;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loop});p.hook(loop,Store(loop+1),length=1);p.hook(loop+1,Sm83DecRegister("c",loop+2),length=1);p.hook(loop+4,Bound(RETURN),length=1);s=p.factory.blank_state(addr=loop);set_assembly_registers(s,i);s.globals["written"]=i["written"];m=p.factory.simulation_manager(s);m.stashes["found"]=[]
 while m.active:
  m.move(from_stash="active",to_stash="found",filter_func=lambda x:x.addr in {LOOP,RETURN})
  if m.active:m.step()
 return [E(**assembly_registers(x),written=x.globals["written"],cont=claripy.BVV(1 if x.addr==LOOP else 0,8),constraints=tuple(x.solver.constraints)) for x in m.found]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_begin()->None:
 i=symbolic_registers("intro_black_begin");i["written"]=claripy.BVS("intro_black_begin_written",8);assert_pathwise_equivalent([begin(i)],native("port_intro_place_black_tiles_begin",i,False),(*REGISTERS,"cont"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_step()->None:
 i=symbolic_registers("intro_black_step");i["written"]=claripy.BVS("intro_black_step_written",8);assert_pathwise_equivalent(step(i),native("port_intro_place_black_tiles_step",i,True),(*REGISTERS,"written","cont"))
def test_body()->None:
 loc=symbol_location(SYMBOLS,"IntroPlaceBlackTiles");assert linked_bytes(ROM,loc,7)==bytes.fromhex("3e01220d20fcc9")
