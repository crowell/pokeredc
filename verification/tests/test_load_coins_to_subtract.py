from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair, Sm83AddRegister, Sm83LoadAImmediate, Sm83StoreAHighImmediate

ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";STACK=0xd000;RETURN=0xffff;NATIVE_STATE=0x100000
NAMES=("wWhichPrize","hUnusedCoinsByte","hCoins","hCoins")

class XorA(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:self.state.regs.a=0;self.state.regs.f=0x40;self.jump(self.n)  # type: ignore[override]
class Fetch(angr.SimProcedure):
 def __init__(self,n:int,key:str,increment:bool)->None:super().__init__();self.n=n;self.key=key;self.increment=increment
 def run(self)->None:  # type: ignore[override]
  self.state.regs.a=self.state.globals[self.key]
  if self.increment:self.state.regs.hl=self.state.regs.hl+1
  self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(i:dict[str,claripy.ast.BV])->list[E]:
 loc=symbol_location(SYMBOLS,"LoadCoinsToSubtract");which=symbol_location(SYMBOLS,"wWhichPrize").address;unused=symbol_location(SYMBOLS,"hUnusedCoinsByte").address;coins=symbol_location(SYMBOLS,"hCoins").address
 p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address})
 p.hook(loc.address,Sm83LoadAImmediate(which,loc.address+3),length=3);p.hook(loc.address+3,Sm83AddRegister("a",loc.address+4),length=1);p.hook(loc.address+10,Sm83AddHlRegisterPair("de",loc.address+11),length=1);p.hook(loc.address+11,XorA(loc.address+12),length=1);p.hook(loc.address+12,Sm83StoreAHighImmediate(unused,loc.address+14),length=2);p.hook(loc.address+14,Fetch(loc.address+15,"fetched_high",True),length=1);p.hook(loc.address+15,Sm83StoreAHighImmediate(coins,loc.address+17),length=2);p.hook(loc.address+17,Fetch(loc.address+18,"fetched_low",False),length=1);p.hook(loc.address+18,Sm83StoreAHighImmediate(coins+1,loc.address+20),length=2)
 s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.memory.store(which,i["which"]);s.memory.store(unused,i["unused"]);s.memory.store(coins,i["coins_high"]);s.memory.store(coins+1,i["coins_low"]);s.globals["fetched_high"]=i["fetched_high"];s.globals["fetched_low"]=i["fetched_low"];s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness="Iend_LE")
 ends=collect_returns(p,s,RETURN);return [E(**assembly_registers(x),memory=claripy.Concat(x.memory.load(which,1),x.memory.load(unused,1),x.memory.load(coins,1),x.memory.load(coins+1,1),i["fetched_high"],i["fetched_low"]),constraints=tuple(x.solver.constraints)) for x in ends]
def native(i:dict[str,claripy.ast.BV])->list[E]:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_load_coins_to_subtract");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for n,key in enumerate(("which","unused","coins_high","coins_low","fetched_high","fetched_low")):s.memory.store(NATIVE_STATE+8+n,i[key])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=claripy.Concat(*(x.memory.load(NATIVE_STATE+8+n,1) for n in range(6))),constraints=tuple(x.solver.constraints)) for x in m.deadended]
def inputs()->dict[str,claripy.ast.BV]:
 i=symbolic_registers("load_coins")
 for key in ("which","unused","coins_high","coins_low","fetched_high","fetched_low"):i[key]=claripy.BVS("load_coins_"+key,8)
 return i
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_equivalence()->None:
 i=inputs();assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,"memory"))
def test_body()->None:
 loc=symbol_location(SYMBOLS,"LoadCoinsToSubtract");assert linked_bytes(ROM,loc,21)==bytes.fromhex("fa39d18716005f2141d119afe09f2ae0a07ee0a1c9")
