from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83DecRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;LOOP=0xeffe;RETURN=0xefff
SPECS=(("BattleTransition_VerticalStripes_","port_battle_transition_vertical_stripes",2,False),("BattleTransition_HorizontalStripes_","port_battle_transition_horizontal_stripes",5,True))
class Store(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):  # type: ignore[override]
  if self.state.globals.get("entered",False):self.jump(LOOP);return
  self.state.globals["entered"]=True;self.state.globals["written"]=claripy.BVV(0xff,8);self.jump(self.n)
class Bound(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;written:claripy.ast.BV;cont:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def native(sym,i,ret=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i["written"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),written=x.memory.load(NATIVE_STATE+8,1),cont=(claripy.If(x.regs.rax[7:0]==0,claripy.BVV(1,8),claripy.BVV(0,8)) if ret else claripy.BVV(1,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
def begin(symbol,i,loop_offset):
 loc=symbol_location(SYMBOLS,symbol);p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address+loop_offset,Bound(LOOP),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);m=p.factory.simulation_manager(s);m.explore(find=LOOP);x=m.found[0];return E(**assembly_registers(x),written=i["written"],cont=claripy.BVV(1,8),constraints=tuple(x.solver.constraints))
def step(symbol,i,loop_offset,uses_add):
 loc=symbol_location(SYMBOLS,symbol);loop=loc.address+loop_offset;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loop});p.hook(loop,Store(loop+2),length=2)
 if uses_add:p.hook(loop+2,Sm83AddHlRegisterPair("de",loop+3),length=1);dec=loop+3
 else:dec=loop+4
 p.hook(dec,Sm83DecRegister("c",dec+1),length=1);p.hook(dec+3,Bound(RETURN),length=1);s=p.factory.blank_state(addr=loop);set_assembly_registers(s,i);s.globals["written"]=i["written"];m=p.factory.simulation_manager(s);m.stashes["found"]=[]
 while m.active:
  m.move(from_stash="active",to_stash="found",filter_func=lambda x:x.addr in {LOOP,RETURN})
  if m.active:m.step()
 return [E(**assembly_registers(x),written=x.globals["written"],cont=claripy.BVV(1 if x.addr==LOOP else 0,8),constraints=tuple(x.solver.constraints)) for x in m.found]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
@pytest.mark.parametrize("symbol,port,loop_offset,uses_add",SPECS)
def test_begin(symbol,port,loop_offset,uses_add):
 i=symbolic_registers(symbol+"_begin");i["written"]=claripy.BVS(symbol+"_begin_written",8);assert_pathwise_equivalent([begin(symbol,i,loop_offset)],native(port+"_begin",i),(*REGISTERS,"cont"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
@pytest.mark.parametrize("symbol,port,loop_offset,uses_add",SPECS)
def test_step(symbol,port,loop_offset,uses_add):
 i=symbolic_registers(symbol+"_step");i["written"]=claripy.BVS(symbol+"_step_written",8);assert_pathwise_equivalent(step(symbol,i,loop_offset,uses_add),native(port+"_step",i,True),(*REGISTERS,"written","cont"))
def test_bodies():
 for symbol,body in (("BattleTransition_VerticalStripes_","0e0a36ff23230d20f9c9"),("BattleTransition_HorizontalStripes_","0e0911280036ff190d20fac9")):
  expected=bytes.fromhex(body);assert linked_bytes(ROM,symbol_location(SYMBOLS,symbol),len(expected))==expected
