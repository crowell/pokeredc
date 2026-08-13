from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83SetAtHl,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];VERIFY=ROOT/"verification";NATIVE_ELF=VERIFY/"build"/"ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";STACK=0xd000;RETURN=0xffff;NATIVE_STATE=0x100000
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(i:dict[str,claripy.ast.BV])->Endpoint:
 loc=symbol_location(SYMBOLS,"StartSimulatingJoypadStates");names=("wOverrideSimulatedJoypadStatesMask","wSpritePlayerStateData2MovementByte1","wStatusFlags5");addrs=tuple(symbol_location(SYMBOLS,n).address for n in names);p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address})
 p.hook(loc.address+1,Sm83StoreAImmediate(addrs[0],loc.address+4),length=3);p.hook(loc.address+4,Sm83StoreAImmediate(addrs[1],loc.address+7),length=3);p.hook(loc.address+10,Sm83SetAtHl(7,loc.address+12),length=2)
 s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i)
 for x,a in enumerate(addrs):s.memory.store(a,i[f"memory{x}"])
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness="Iend_LE");ends=collect_returns(p,s,RETURN);assert len(ends)==1;e=ends[0]
 return Endpoint(**assembly_registers(e),memory=claripy.Concat(*(e.memory.load(a,1) for a in addrs)),constraints=tuple(e.solver.constraints))
def native(i:dict[str,claripy.ast.BV])->Endpoint:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_start_simulating_joypad_states");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for x in range(3):s.memory.store(NATIVE_STATE+8+x,i[f"memory{x}"])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1;e=m.deadended[0];return Endpoint(**native_registers(e,NATIVE_STATE),memory=e.memory.load(NATIVE_STATE+8,3),constraints=tuple(e.solver.constraints))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_equivalence()->None:
 i=symbolic_registers("start_simulating_joypad");
 for x in range(3):i[f"memory{x}"]=claripy.BVS(f"start_sim_memory{x}",8)
 assert_pathwise_equivalent([assembly(i)],[native(i)],(*REGISTERS,"memory"))
def test_body()->None:
 loc=symbol_location(SYMBOLS,"StartSimulatingJoypadStates");assert linked_bytes(ROM,loc,13)==bytes.fromhex("afea3bcdea06c22130d7cbfec9")
