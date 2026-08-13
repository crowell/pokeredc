from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;BOUNDARY=0xeffe
class LoadDe(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:self.state.regs.a=self.state.globals["fetched"];self.jump(self.n)  # type: ignore[override]
class IncDe(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:self.state.regs.de=self.state.regs.de+1;self.jump(self.n)  # type: ignore[override]
class StoreHlInc(angr.SimProcedure):
 def run(self)->None:  # type: ignore[override]
  self.state.globals["written"]=self.state.regs.a;self.state.regs.hl=self.state.regs.hl+1;self.jump(BOUNDARY)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;written:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(i:dict[str,claripy.ast.BV])->E:
 loc=symbol_location(SYMBOLS,"CopyHealingMachineOAM");p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address,LoadDe(loc.address+1),length=1);p.hook(loc.address+1,IncDe(loc.address+2),length=1);p.hook(loc.address+2,StoreHlInc(),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.globals["fetched"]=i["fetched"];s.globals["written"]=i["written"];m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);assert not m.errored and len(m.found)==1;x=m.found[0];return E(**assembly_registers(x),written=x.globals["written"],constraints=tuple(x.solver.constraints))
def native(i:dict[str,claripy.ast.BV])->E:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_copy_healing_machine_oam_step");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE,claripy.ZeroExt(56,i["fetched"]));store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i["written"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1;x=m.deadended[0];return E(**native_registers(x,NATIVE_STATE),written=x.memory.load(NATIVE_STATE+8,1),constraints=tuple(x.solver.constraints))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_one_step_equivalence()->None:
 i=symbolic_registers("healing_oam_step");i["fetched"]=claripy.BVS("healing_oam_fetched",8);i["written"]=claripy.BVS("healing_oam_written",8);assert_pathwise_equivalent([assembly(i)],[native(i)],(*REGISTERS,"written"))
def test_exact_unrolled_body()->None:
 loc=symbol_location(SYMBOLS,"CopyHealingMachineOAM");assert linked_bytes(ROM,loc,13)==bytes.fromhex("1a13221a13221a13221a1322c9")
