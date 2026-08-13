from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83SetAtHl,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;GB_STACK=0xd000;GB_RETURN=0xffff
ADDRESSES=(0xd730,0xccd3,0xcd38,0xc206,0xcd3b)
CASES=(("Route6GateMovePlayerDownScript","port_route_6_gate_move_player_down","2130d7cbfe3e80ead3cc3e01ea38cdafea06c2ea3bcdc9"),("Route7GateMovePlayerLeftScript","port_route_7_gate_move_player_left","2130d7cbfe3e20ead3cc3e01ea38cdafea06c2ea3bcdc9"),("Route8GateMovePlayerRightScript","port_route_8_gate_move_player_right","2130d7cbfe3e10ead3cc3e01ea38cdafea06c2ea3bcdc9"))
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
class XorA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=0;self.state.regs.f=0x40;self.jump(self.n)  # type: ignore[override]
def inputs(prefix):
 i=symbolic_registers(prefix)
 for x in range(5):i[f"memory{x}"]=claripy.BVS(f"{prefix}_memory{x}",8)
 return i
def assembly(symbol,i):
 loc=symbol_location(SYMBOLS,symbol);p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});b=loc.address
 p.hook(b+3,Sm83SetAtHl(7,b+5),length=2);p.hook(b+7,Sm83StoreAImmediate(ADDRESSES[1],b+10),length=3);p.hook(b+12,Sm83StoreAImmediate(ADDRESSES[2],b+15),length=3);p.hook(b+15,XorA(b+16),length=1);p.hook(b+16,Sm83StoreAImmediate(ADDRESSES[3],b+19),length=3);p.hook(b+19,Sm83StoreAImmediate(ADDRESSES[4],b+22),length=3)
 s=p.factory.blank_state(addr=b);set_assembly_registers(s,i)
 for x,a in enumerate(ADDRESSES):s.memory.store(a,i[f"memory{x}"])
 s.regs.sp=GB_STACK;s.memory.store(GB_STACK,claripy.BVV(GB_RETURN,16),endness="Iend_LE");ends=collect_returns(p,s,GB_RETURN)
 return [E(**assembly_registers(x),memory=claripy.Concat(*(x.memory.load(a,1) for a in ADDRESSES)),constraints=tuple(x.solver.constraints)) for x in ends]
def native(symbol,i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(symbol);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[f"memory{x}"] for x in range(5))));m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,5),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
@pytest.mark.parametrize("symbol,c_symbol,_body",CASES)
def test_equivalence(symbol,c_symbol,_body):
 i=inputs(symbol.lower());assert_pathwise_equivalent(assembly(symbol,i),native(c_symbol,i),(*REGISTERS,"memory"))
@pytest.mark.parametrize("symbol,_c_symbol,body",CASES)
def test_exact_body(symbol,_c_symbol,body):
 expected=bytes.fromhex(body);assert linked_bytes(ROM,symbol_location(SYMBOLS,symbol),len(expected))==expected
