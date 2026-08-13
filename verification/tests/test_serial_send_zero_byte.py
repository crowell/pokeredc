from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate,Sm83LoadAHighImmediate,Sm83StoreAHighImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";STACK=0xd000;RETURN=0xffff;NATIVE_STATE=0x100000
class XorA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=0;self.state.regs.f=0x40;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(i):
 loc=symbol_location(SYMBOLS,"Serial_SendZeroByte");send=symbol_location(SYMBOLS,"hSerialSendData").address;connection=symbol_location(SYMBOLS,"hSerialConnectionStatus").address;control=0xff02;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address,XorA(loc.address+1),length=1);p.hook(loc.address+1,Sm83StoreAHighImmediate(send,loc.address+3),length=2);p.hook(loc.address+3,Sm83LoadAHighImmediate(connection,loc.address+5),length=2);p.hook(loc.address+5,Sm83CpImmediate(2,loc.address+7),length=2);p.hook(loc.address+10,Sm83StoreAHighImmediate(control,loc.address+12),length=2);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.memory.store(send,i["send"]);s.memory.store(connection,i["connection"]);s.memory.store(control,i["control"]);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness="Iend_LE");ends=collect_returns(p,s,RETURN);return [E(**assembly_registers(x),memory=claripy.Concat(x.memory.load(send,1),x.memory.load(connection,1),x.memory.load(control,1)),constraints=tuple(x.solver.constraints)) for x in ends]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_serial_send_zero_byte");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for n,key in enumerate(("send","connection","control")):s.memory.store(NATIVE_STATE+8+n,i[key])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=claripy.Concat(*(x.memory.load(NATIVE_STATE+8+n,1) for n in range(3))),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_equivalence():
 i=symbolic_registers("serial_zero")
 for key in ("send","connection","control"):i[key]=claripy.BVS("serial_zero_"+key,8)
 assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,"memory"))
def test_body():
 loc=symbol_location(SYMBOLS,"Serial_SendZeroByte");assert linked_bytes(ROM,loc,13)==bytes.fromhex("afe0acf0aafe02c03e81e002c9")
