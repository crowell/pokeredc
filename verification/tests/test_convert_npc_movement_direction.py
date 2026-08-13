from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate,Sm83CpRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;CONTINUE=0xeffc;MATCH=0xeffd;TERMINATOR=0xeffe;BOUNDARY=0xefff
class Bound(angr.SimProcedure):
 def __init__(self,target:int)->None:super().__init__();self.target=target
 def run(self)->None:self.jump(self.target)  # type: ignore[override]
class Fetch(angr.SimProcedure):
 def __init__(self,n:int,key:str,increment:bool=False,reentry:bool=False)->None:super().__init__();self.n=n;self.key=key;self.increment=increment;self.reentry=reentry
 def run(self)->None:  # type: ignore[override]
  if self.reentry and self.state.globals.get("entered",False):self.jump(CONTINUE);return
  self.state.globals["entered"]=True;self.state.regs.a=self.state.globals[self.key]
  if self.increment:self.state.regs.hl=self.state.regs.hl+1
  self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def native(sym:str,i:dict[str,claripy.ast.BV],ret:bool=False)->list[E]:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i["direction"]);s.memory.store(NATIVE_STATE+9,i["mask"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=claripy.Concat(x.memory.load(NATIVE_STATE+8,1),x.memory.load(NATIVE_STATE+9,1)),result=(x.regs.rax[7:0] if ret else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
def ep(x,i,result):return E(**assembly_registers(x),memory=claripy.Concat(i["direction"],i["mask"]),result=claripy.BVV(result,8),constraints=tuple(x.solver.constraints))
def proj(loc):return angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address})
def begin(i):
 loc=symbol_location(SYMBOLS,"ConvertNPCMovementDirectionToJoypadMask");p=proj(loc);p.hook(loc.address+5,Bound(BOUNDARY),length=1);s=p.factory.blank_state(addr=loc.address+1);set_assembly_registers(s,i);m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);return ep(m.found[0],i,0)
def step(i):
 loc=symbol_location(SYMBOLS,"ConvertNPCMovementDirectionToJoypadMask");loop=loc.address+5;p=proj(loc);p.hook(loop,Fetch(loop+1,"direction",True,True),length=1);p.hook(loop+1,Sm83CpImmediate(0xff,loop+3),length=2);p.hook(loop+5,Sm83CpRegister("b",loop+6),length=1);p.hook(loop+11,Bound(MATCH),length=1);p.hook(loop+12,Bound(TERMINATOR),length=1);s=p.factory.blank_state(addr=loop);set_assembly_registers(s,i);s.globals["direction"]=i["direction"];m=p.factory.simulation_manager(s);m.stashes["found"]=[]
 while m.active:
  m.move(from_stash="active",to_stash="found",filter_func=lambda x:x.addr in {CONTINUE,MATCH,TERMINATOR})
  if m.active:m.step()
 return [ep(x,i,{CONTINUE:0,MATCH:1,TERMINATOR:2}[x.addr]) for x in m.found]
def load_mask(i):
 loc=symbol_location(SYMBOLS,"ConvertNPCMovementDirectionToJoypadMask");start=loc.address+16;p=proj(loc);p.hook(start,Fetch(BOUNDARY,"mask"),length=1);s=p.factory.blank_state(addr=start);set_assembly_registers(s,i);s.globals["mask"]=i["mask"];m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);return ep(m.found[0],i,0)
def inputs(prefix):
 i=symbolic_registers(prefix);i["direction"]=claripy.BVS(prefix+"_direction",8);i["mask"]=claripy.BVS(prefix+"_mask",8);return i
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_begin():
 i=inputs("movement_direction_begin");assert_pathwise_equivalent([begin(i)],native("port_convert_npc_movement_direction_begin",i),(*REGISTERS,"memory"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_step():
 i=inputs("movement_direction_step");assert_pathwise_equivalent(step(i),native("port_convert_npc_movement_direction_step",i,True),(*REGISTERS,"memory","result"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_load_mask():
 i=inputs("movement_direction_mask");assert_pathwise_equivalent([load_mask(i)],native("port_convert_npc_movement_direction_load_mask",i),(*REGISTERS,"memory"))
def test_body():
 loc=symbol_location(SYMBOLS,"ConvertNPCMovementDirectionToJoypadMask");assert linked_bytes(ROM,loc,19)==bytes.fromhex("e54721d2792afeff2807b828032318f57ee1c9")
