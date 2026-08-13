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
class LoadComputed(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:self.state.regs.a=self.state.globals["fetched"];self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;value:claripy.ast.BV;fetched:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(i:dict[str,claripy.ast.BV])->E:
 loc=symbol_location(SYMBOLS,"TMToMove");value=symbol_location(SYMBOLS,"wTempTMHM").address;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address,Sm83LoadAImmediate(value,loc.address+3),length=3);p.hook(loc.address+3,Sm83DecRegister("a",loc.address+4),length=1);p.hook(loc.address+10,Sm83AddHlRegisterPair("bc",loc.address+11),length=1);p.hook(loc.address+11,LoadComputed(loc.address+12),length=1);p.hook(loc.address+12,Sm83StoreAImmediate(value,loc.address+15),length=3);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.memory.store(value,i["value"]);s.globals["fetched"]=i["fetched"];s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness="Iend_LE");ends=collect_returns(p,s,RETURN);assert len(ends)==1;x=ends[0];return E(**assembly_registers(x),value=x.memory.load(value,1),fetched=i["fetched"],constraints=tuple(x.solver.constraints))
def native(i:dict[str,claripy.ast.BV])->E:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_tm_to_move");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i["value"]);s.memory.store(NATIVE_STATE+9,i["fetched"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1;x=m.deadended[0];return E(**native_registers(x,NATIVE_STATE),value=x.memory.load(NATIVE_STATE+8,1),fetched=x.memory.load(NATIVE_STATE+9,1),constraints=tuple(x.solver.constraints))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_equivalence()->None:
 i=symbolic_registers("tm_to_move");i["value"]=claripy.BVS("tm_number",8);i["fetched"]=claripy.BVS("tm_move_fetched",8);assert_pathwise_equivalent([assembly(i)],[native(i)],(*REGISTERS,"value","fetched"))
def test_body()->None:
 loc=symbol_location(SYMBOLS,"TMToMove");value=symbol_location(SYMBOLS,"wTempTMHM").address;table=symbol_location(SYMBOLS,"TechnicalMachines").address;expected=bytes((0xfa,value&0xff,value>>8,0x3d,0x21,table&0xff,table>>8))+bytes.fromhex("06004f097e")+bytes((0xea,value&0xff,value>>8,0xc9));assert linked_bytes(ROM,loc,len(expected))==expected
