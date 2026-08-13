from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AddRegister,Sm83LoadAImmediate,Sm83StoreAHighImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";STACK=0xd000;RETURN=0xffff;NATIVE_STATE=0x100000
class Fetch(angr.SimProcedure):
 def __init__(self,n:int,index:int,increment:bool)->None:super().__init__();self.n=n;self.index=index;self.increment=increment
 def run(self)->None:  # type: ignore[override]
  self.state.regs.a=self.state.globals["fetched"][self.index]
  if self.increment:self.state.regs.hl=self.state.regs.hl+1
  self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(i:dict[str,claripy.ast.BV])->list[E]:
 loc=symbol_location(SYMBOLS,"LoadVendingMachineItem");current=symbol_location(SYMBOLS,"wCurrentMenuItem").address;item=symbol_location(SYMBOLS,"hVendingMachineItem").address;price=symbol_location(SYMBOLS,"hVendingMachinePrice").address;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address})
 p.hook(loc.address+3,Sm83LoadAImmediate(current,loc.address+6),length=3);p.hook(loc.address+6,Sm83AddRegister("a",loc.address+7),length=1);p.hook(loc.address+7,Sm83AddRegister("a",loc.address+8),length=1);p.hook(loc.address+11,Sm83AddHlRegisterPair("de",loc.address+12),length=1)
 for index,(fetch_offset,store_offset,address) in enumerate(((12,13,item),(15,16,price),(18,19,price+1),(21,22,price+2))):p.hook(loc.address+fetch_offset,Fetch(loc.address+store_offset,index,index!=3),length=1);p.hook(loc.address+store_offset,Sm83StoreAHighImmediate(address,loc.address+store_offset+2),length=2)
 s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.memory.store(current,i["current"]);outputs=(item,price,price+1,price+2)
 for n,address in enumerate(outputs):s.memory.store(address,i[f"output{n}"])
 s.globals["fetched"]=[i[f"fetched{n}"] for n in range(4)];s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness="Iend_LE");ends=collect_returns(p,s,RETURN);return [E(**assembly_registers(x),memory=claripy.Concat(x.memory.load(current,1),*(x.memory.load(a,1) for a in outputs),*(i[f"fetched{n}"] for n in range(4))),constraints=tuple(x.solver.constraints)) for x in ends]
def native(i:dict[str,claripy.ast.BV])->list[E]:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_load_vending_machine_item");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);keys=("current",*(f"output{n}" for n in range(4)),*(f"fetched{n}" for n in range(4)))
 for n,key in enumerate(keys):s.memory.store(NATIVE_STATE+8+n,i[key])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=claripy.Concat(*(x.memory.load(NATIVE_STATE+8+n,1) for n in range(9))),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_equivalence()->None:
 i=symbolic_registers("load_vending")
 for key in ("current",*(f"output{n}" for n in range(4)),*(f"fetched{n}" for n in range(4))):i[key]=claripy.BVS("load_vending_"+key,8)
 assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,"memory"))
def test_body()->None:
 loc=symbol_location(SYMBOLS,"LoadVendingMachineItem");assert linked_bytes(ROM,loc,25)==bytes.fromhex("210050fa26cc878716005f192ae0db2ae0dc2ae0dd7ee0dec9")
