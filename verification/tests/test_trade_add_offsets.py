from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83DecRegister,Sm83LoadAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;LOOP=0xeffe;RETURN=0xefff
class Bound(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)  # type: ignore[override]
class StartLoad(angr.SimProcedure):
 def __init__(self,n,address):super().__init__();self.n=n;self.address=address
 def run(self):  # type: ignore[override]
  if self.state.globals.get("entered",False):self.jump(LOOP);return
  self.state.regs.a=self.state.memory.load(self.address,1);self.jump(self.n)
class AddMemory(angr.SimProcedure):
 def __init__(self,n,index):super().__init__();self.n=n;self.index=index
 def run(self):  # type: ignore[override]
  left=self.state.regs.a;right=self.state.globals["coords"][self.index];wide=claripy.ZeroExt(1,left)+claripy.ZeroExt(1,right);result=wide[7:0];flags=claripy.If(result==0,claripy.BVV(0x40,8),claripy.BVV(0,8));flags|=claripy.If((left&0xf)+(right&0xf)>0xf,claripy.BVV(0x10,8),claripy.BVV(0,8));flags|=claripy.ZeroExt(7,wide[8]);self.state.regs.a=result;self.state.regs.f=flags;self.jump(self.n)
class Store(angr.SimProcedure):
 def __init__(self,n,index):super().__init__();self.n=n;self.index=index
 def run(self):  # type: ignore[override]
  if self.index==0 and self.state.globals.get("entered",False):self.jump(LOOP);return
  self.state.globals["entered"]=True;self.state.globals["coords"][self.index]=self.state.regs.a;self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;cont:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def addresses():return (symbol_location(SYMBOLS,"wBaseCoordY").address,symbol_location(SYMBOLS,"wBaseCoordX").address)
def native(sym,i,ret=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for n,key in enumerate(("base_y","base_x","y","x")):s.memory.store(NATIVE_STATE+8+n,i[key])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=claripy.Concat(*(x.memory.load(NATIVE_STATE+8+n,1) for n in range(4))),cont=(claripy.If(x.regs.rax[7:0]==0,claripy.BVV(1,8),claripy.BVV(0,8)) if ret else claripy.BVV(1,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
def begin(i):
 loc=symbol_location(SYMBOLS,"Trade_AddOffsetsToOAMCoords");p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address+5,Bound(LOOP),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);m=p.factory.simulation_manager(s);m.explore(find=LOOP);x=m.found[0];return E(**assembly_registers(x),memory=claripy.Concat(i["base_y"],i["base_x"],i["y"],i["x"]),cont=claripy.BVV(1,8),constraints=tuple(x.solver.constraints))
def step(i):
 loc=symbol_location(SYMBOLS,"Trade_AddOffsetsToOAMCoords");loop=loc.address+5;a=addresses();p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loop});p.hook(loop,StartLoad(loop+3,a[0]),length=3);p.hook(loop+3,AddMemory(loop+4,0),length=1);p.hook(loop+4,Store(loop+5,0),length=1);p.hook(loop+5,Sm83LoadAImmediate(a[1],loop+8),length=3);p.hook(loop+8,AddMemory(loop+9,1),length=1);p.hook(loop+9,Store(loop+10,1),length=1);p.hook(loop+12,Sm83DecRegister("c",loop+13),length=1);p.hook(loop+15,Bound(RETURN),length=1);s=p.factory.blank_state(addr=loop);set_assembly_registers(s,i);s.memory.store(a[0],i["base_y"]);s.memory.store(a[1],i["base_x"]);s.globals["coords"]=[i["y"],i["x"]];m=p.factory.simulation_manager(s);m.stashes["found"]=[]
 while m.active:
  m.move(from_stash="active",to_stash="found",filter_func=lambda x:x.addr in {LOOP,RETURN})
  if m.active:m.step()
 return [E(**assembly_registers(x),memory=claripy.Concat(x.memory.load(a[0],1),x.memory.load(a[1],1),*x.globals["coords"]),cont=claripy.BVV(1 if x.addr==LOOP else 0,8),constraints=tuple(x.solver.constraints)) for x in m.found]
def inputs(prefix):
 i=symbolic_registers(prefix)
 for key in ("base_y","base_x","y","x"):i[key]=claripy.BVS(prefix+"_"+key,8)
 return i
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_begin():
 i=inputs("trade_offsets_begin");assert_pathwise_equivalent([begin(i)],native("port_trade_add_offsets_to_oam_coords_begin",i),(*REGISTERS,"memory","cont"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_step():
 i=inputs("trade_offsets_step");assert_pathwise_equivalent(step(i),native("port_trade_add_offsets_to_oam_coords_step",i,True),(*REGISTERS,"memory","cont"))
def test_body():
 loc=symbol_location(SYMBOLS,"Trade_AddOffsetsToOAMCoords");assert linked_bytes(ROM,loc,21)==bytes.fromhex("2100c30e14fa82d08622fa81d0862223230d20f1c9")
