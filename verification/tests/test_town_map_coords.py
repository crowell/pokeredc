from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddImmediate,Sm83AndImmediate,Sm83SrlRegister,Sm83SwapRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;BOUNDARY=0xefff
class SaveAf(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:self.state.globals["saved_a"]=self.state.regs.a;self.state.globals["saved_f"]=self.state.regs.f;self.jump(self.n)  # type: ignore[override]
class RestoreAf(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:self.state.regs.a=self.state.globals["saved_a"];self.state.regs.f=self.state.globals["saved_f"];self.jump(self.n)  # type: ignore[override]
class StoreHli(angr.SimProcedure):
 def __init__(self,n:int,index:int)->None:super().__init__();self.n=n;self.index=index
 def run(self)->None:self.state.globals[f"memory{self.index}"]=self.state.regs.a;self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
class Done(angr.SimProcedure):
 def run(self)->None:self.jump(BOUNDARY)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(i:dict[str,claripy.ast.BV])->E:
 loc=symbol_location(SYMBOLS,"TownMapCoordsToOAMCoords");p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address,SaveAf(loc.address+1),length=1);p.hook(loc.address+1,Sm83AndImmediate(0xf0,loc.address+3),length=2);p.hook(loc.address+3,Sm83SrlRegister("a",loc.address+5),length=2);p.hook(loc.address+5,Sm83AddImmediate(24,loc.address+7),length=2);p.hook(loc.address+8,StoreHli(loc.address+9,0),length=1);p.hook(loc.address+9,RestoreAf(loc.address+10),length=1);p.hook(loc.address+10,Sm83AndImmediate(0x0f,loc.address+12),length=2);p.hook(loc.address+12,Sm83SwapRegister("a",loc.address+14),length=2);p.hook(loc.address+14,Sm83SrlRegister("a",loc.address+16),length=2);p.hook(loc.address+16,Sm83AddImmediate(24,loc.address+18),length=2);p.hook(loc.address+19,StoreHli(loc.address+20,1),length=1);p.hook(loc.address+20,Done(),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.globals["memory0"]=i["memory0"];s.globals["memory1"]=i["memory1"];m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);assert not m.errored and len(m.found)==1;x=m.found[0];return E(**assembly_registers(x),memory=claripy.Concat(x.globals["memory0"],x.globals["memory1"]),constraints=tuple(x.solver.constraints))
def native(i:dict[str,claripy.ast.BV])->E:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_town_map_coords_to_oam_coords");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i["memory0"]);s.memory.store(NATIVE_STATE+9,i["memory1"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1;x=m.deadended[0];return E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,2),constraints=tuple(x.solver.constraints))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_equivalence()->None:
 i=symbolic_registers("town_map_coords");i["memory0"]=claripy.BVS("town_map_y_dest",8);i["memory1"]=claripy.BVS("town_map_x_dest",8);assert_pathwise_equivalent([assembly(i)],[native(i)],(*REGISTERS,"memory"))
def test_body()->None:
 loc=symbol_location(SYMBOLS,"TownMapCoordsToOAMCoords");assert linked_bytes(ROM,loc,21)==bytes.fromhex("f5e6f0cb3fc6184722f1e60fcb37cb3fc6184f22c9")
