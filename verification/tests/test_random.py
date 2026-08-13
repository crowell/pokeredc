from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AdcRegister,Sm83LoadAHighImmediate,Sm83SbcRegister,Sm83StoreAHighImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";STACK=0xd000;RETURN=0xffff;NATIVE_STATE=0x100000
class LoadDiv(angr.SimProcedure):
 def __init__(self,n,index):super().__init__();self.n=n;self.index=index
 def run(self):self.state.regs.a=self.state.globals["div"][self.index];self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(i):
 loc=symbol_location(SYMBOLS,"Random_");add=symbol_location(SYMBOLS,"hRandomAdd").address;sub=symbol_location(SYMBOLS,"hRandomSub").address;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address,LoadDiv(loc.address+2,0),length=2);p.hook(loc.address+3,Sm83LoadAHighImmediate(add,loc.address+5),length=2);p.hook(loc.address+5,Sm83AdcRegister("b",loc.address+6),length=1);p.hook(loc.address+6,Sm83StoreAHighImmediate(add,loc.address+8),length=2);p.hook(loc.address+8,LoadDiv(loc.address+10,1),length=2);p.hook(loc.address+11,Sm83LoadAHighImmediate(sub,loc.address+13),length=2);p.hook(loc.address+13,Sm83SbcRegister("b",loc.address+14),length=1);p.hook(loc.address+14,Sm83StoreAHighImmediate(sub,loc.address+16),length=2);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.memory.store(add,i["add"]);s.memory.store(sub,i["sub"]);s.globals["div"]=[i["div0"],i["div1"]];s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness="Iend_LE");ends=collect_returns(p,s,RETURN);return [E(**assembly_registers(x),memory=claripy.Concat(x.memory.load(add,1),x.memory.load(sub,1),i["div0"],i["div1"]),constraints=tuple(x.solver.constraints)) for x in ends]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_random");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for n,key in enumerate(("add","sub","div0","div1")):s.memory.store(NATIVE_STATE+8+n,i[key])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=claripy.Concat(*(x.memory.load(NATIVE_STATE+8+n,1) for n in range(4))),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_equivalence():
 i=symbolic_registers("random")
 for key in ("add","sub","div0","div1"):i[key]=claripy.BVS("random_"+key,8)
 assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,"memory"))
def test_body():
 loc=symbol_location(SYMBOLS,"Random_");assert linked_bytes(ROM,loc,17)==bytes.fromhex("f00447f0d388e0d3f00447f0d498e0d4c9")
