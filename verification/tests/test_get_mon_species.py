from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83DecRegister,Sm83LoadAImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";STACK=0xd000;RETURN=0xffff;NATIVE_STATE=0x100000
class Fetch(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:self.state.regs.a=self.state.globals["fetched"];self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;data_location:claripy.ast.BV;fetched:claripy.ast.BV;species:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(i:dict[str,claripy.ast.BV])->list[E]:
 loc=symbol_location(SYMBOLS,"GetMonSpecies");data=symbol_location(SYMBOLS,"wMonDataLocation").address;species=symbol_location(SYMBOLS,"wCurPartySpecies").address;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address+3,Sm83LoadAImmediate(data,loc.address+6),length=3);p.hook(loc.address+9,Sm83DecRegister("a",loc.address+10),length=1);p.hook(loc.address+22,Sm83AddHlRegisterPair("de",loc.address+23),length=1);p.hook(loc.address+23,Fetch(loc.address+24),length=1);p.hook(loc.address+24,Sm83StoreAImmediate(species,loc.address+27),length=3);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.memory.store(data,i["data_location"]);s.memory.store(species,i["species"]);s.globals["fetched"]=i["fetched"];s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness="Iend_LE");ends=collect_returns(p,s,RETURN)
 return [E(**assembly_registers(x),data_location=x.memory.load(data,1),fetched=i["fetched"],species=x.memory.load(species,1),constraints=tuple(x.solver.constraints)) for x in ends]
def native(i:dict[str,claripy.ast.BV])->list[E]:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_get_mon_species");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i["data_location"]);s.memory.store(NATIVE_STATE+9,i["fetched"]);s.memory.store(NATIVE_STATE+10,i["species"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),data_location=x.memory.load(NATIVE_STATE+8,1),fetched=x.memory.load(NATIVE_STATE+9,1),species=x.memory.load(NATIVE_STATE+10,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_equivalence()->None:
 i=symbolic_registers("get_mon_species");i["data_location"]=claripy.BVS("mon_data_location",8);i["fetched"]=claripy.BVS("mon_species_fetched",8);i["species"]=claripy.BVS("initial_cur_species",8);assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,"data_location","fetched","species"))
def test_body()->None:
 loc=symbol_location(SYMBOLS,"GetMonSpecies");assert linked_bytes(ROM,loc,28)==bytes.fromhex("2164d1fa49cca7280b3d28052181da1803219dd81600197eea91cfc9")
