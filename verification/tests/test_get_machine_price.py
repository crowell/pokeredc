from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AndImmediate,Sm83LoadAImmediate,Sm83SrlRegister,Sm83StoreAHighImmediate,Sm83SubImmediate,Sm83SwapRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";STACK=0xd000;RETURN=0xffff;NATIVE_STATE=0x100000
class Fetch(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:self.state.regs.a=self.state.globals["fetched"];self.jump(self.n)  # type: ignore[override]
class XorA(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:self.state.regs.a=0;self.state.regs.f=0x40;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(i):
 loc=symbol_location(SYMBOLS,"GetMachinePrice");item=symbol_location(SYMBOLS,"wCurItem").address;price=symbol_location(SYMBOLS,"hItemPrice").address;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address,Sm83LoadAImmediate(item,loc.address+3),length=3);p.hook(loc.address+3,Sm83SubImmediate(0xc9,loc.address+5),length=2);p.hook(loc.address+10,Sm83SrlRegister("a",loc.address+12),length=2);p.hook(loc.address+15,Sm83AddHlRegisterPair("bc",loc.address+16),length=1);p.hook(loc.address+16,Fetch(loc.address+17),length=1);p.hook(loc.address+17,Sm83SrlRegister("d",loc.address+19),length=2);p.hook(loc.address+21,Sm83SwapRegister("a",loc.address+23),length=2);p.hook(loc.address+23,Sm83AndImmediate(0xf0,loc.address+25),length=2);p.hook(loc.address+25,Sm83StoreAHighImmediate(price+1,loc.address+27),length=2);p.hook(loc.address+27,XorA(loc.address+28),length=1);p.hook(loc.address+28,Sm83StoreAHighImmediate(price,loc.address+30),length=2);p.hook(loc.address+30,Sm83StoreAHighImmediate(price+2,loc.address+32),length=2)
 s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.memory.store(item,i["item"])
 for n in range(3):s.memory.store(price+n,i[f"price{n}"])
 s.globals["fetched"]=i["fetched"];s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness="Iend_LE");ends=collect_returns(p,s,RETURN);return [E(**assembly_registers(x),memory=claripy.Concat(x.memory.load(item,1),*(x.memory.load(price+n,1) for n in range(3)),i["fetched"]),constraints=tuple(x.solver.constraints)) for x in ends]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_get_machine_price");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for n,key in enumerate(("item","price0","price1","price2","fetched")):s.memory.store(NATIVE_STATE+8+n,i[key])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=claripy.Concat(*(x.memory.load(NATIVE_STATE+8+n,1) for n in range(5))),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_equivalence():
 i=symbolic_registers("machine_price")
 for key in ("item","price0","price1","price2","fetched"):i[key]=claripy.BVS("machine_price_"+key,8)
 assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,"memory"))
def test_body():
 loc=symbol_location(SYMBOLS,"GetMachinePrice");assert linked_bytes(ROM,loc,33)==bytes.fromhex("fa91cfd6c9d85721a77fcb3f4f0600097ecb3a3002cb37e6f0e08cafe08be08dc9")
