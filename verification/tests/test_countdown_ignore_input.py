from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate,Sm83BitRegister,Sm83DecRegister,Sm83LoadAImmediate,Sm83ResRegister,Sm83StoreAHighImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";STACK=0xd000;RETURN=0xffff;NATIVE_STATE=0x100000
NAMES=("wIgnoreInputCounter","wStatusFlags5","hJoyPressed","hJoyHeld")
class Zero(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:self.state.regs.a=0;self.state.regs.f=0x40;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(i:dict[str,claripy.ast.BV])->list[E]:
 loc=symbol_location(SYMBOLS,"CountDownIgnoreInputBitReset");a=tuple(symbol_location(SYMBOLS,n).address for n in NAMES);p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address,Sm83LoadAImmediate(a[0],loc.address+3),length=3);p.hook(loc.address+3,Sm83AndImmediate(0xff,loc.address+4),length=1);p.hook(loc.address+10,Sm83DecRegister("a",loc.address+11),length=1);p.hook(loc.address+11,Sm83StoreAImmediate(a[0],loc.address+14),length=3);p.hook(loc.address+14,Sm83AndImmediate(0xff,loc.address+15),length=1);p.hook(loc.address+16,Sm83LoadAImmediate(a[1],loc.address+19),length=3)
 p.hook(loc.address+19,Sm83ResRegister(1,"a",loc.address+21),length=2);p.hook(loc.address+21,Sm83ResRegister(2,"a",loc.address+23),length=2);p.hook(loc.address+23,Sm83BitRegister(5,"a",loc.address+25),length=2);p.hook(loc.address+25,Sm83ResRegister(5,"a",loc.address+27),length=2);p.hook(loc.address+27,Sm83StoreAImmediate(a[1],loc.address+30),length=3);p.hook(loc.address+31,Zero(loc.address+32),length=1);p.hook(loc.address+32,Sm83StoreAHighImmediate(a[2],loc.address+34),length=2);p.hook(loc.address+34,Sm83StoreAHighImmediate(a[3],loc.address+36),length=2);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i)
 for n,v in enumerate(a):s.memory.store(v,i[f"memory{n}"])
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness="Iend_LE");ends=collect_returns(p,s,RETURN);return [E(**assembly_registers(x),memory=claripy.Concat(*(x.memory.load(v,1) for v in a)),constraints=tuple(x.solver.constraints)) for x in ends]
def native(i:dict[str,claripy.ast.BV])->list[E]:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_count_down_ignore_input_bit_reset");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for n in range(4):s.memory.store(NATIVE_STATE+8+n,i[f"memory{n}"])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,4),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_equivalence()->None:
 i=symbolic_registers("countdown_ignore_input")
 for n,name in enumerate(("counter","status","joy_pressed","joy_held")):i[f"memory{n}"]=claripy.BVS("countdown_"+name,8)
 assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,"memory"))
def test_body()->None:
 loc=symbol_location(SYMBOLS,"CountDownIgnoreInputBitReset");assert linked_bytes(ROM,loc,37)==bytes.fromhex("fa3ad1a720043eff18013dea3ad1a7c0fa30d7cb8fcb97cb6fcbafea30d7c8afe0b3e0b4c9")
