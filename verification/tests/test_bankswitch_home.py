from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83LoadAHighImmediate,Sm83LoadAImmediate,Sm83StoreAHighImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];VERIFY=ROOT/"verification";NATIVE_ELF=VERIFY/"build"/"ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";STACK=0xd000;RETURN=0xffff;NATIVE_STATE=0x100000
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def addresses()->tuple[int,...]:return (symbol_location(SYMBOLS,"wBankswitchHomeTemp").address,symbol_location(SYMBOLS,"hLoadedROMBank").address,symbol_location(SYMBOLS,"wBankswitchHomeSavedROMBank").address,0x2000)
def asm(i:dict[str,claripy.ast.BV])->Endpoint:
 loc=symbol_location(SYMBOLS,"BankswitchHome");a=addresses();p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address})
 hooks=((0,Sm83StoreAImmediate,a[0],3),(3,Sm83LoadAHighImmediate,a[1],2),(5,Sm83StoreAImmediate,a[2],3),(8,Sm83LoadAImmediate,a[0],3),(11,Sm83StoreAHighImmediate,a[1],2),(13,Sm83StoreAImmediate,a[3],3))
 for off,proc,addr,n in hooks:p.hook(loc.address+off,proc(addr,loc.address+off+n),length=n)
 s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i)
 for x,addr in enumerate(a):s.memory.store(addr,i[f"memory{x}"])
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness="Iend_LE");ends=collect_returns(p,s,RETURN);assert len(ends)==1;e=ends[0];return Endpoint(**assembly_registers(e),memory=claripy.Concat(*(e.memory.load(addr,1) for addr in a)),constraints=tuple(e.solver.constraints))
def native(i:dict[str,claripy.ast.BV])->Endpoint:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_bankswitch_home");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for x in range(5):s.memory.store(NATIVE_STATE+8+x,i[f"memory{x}"])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1;e=m.deadended[0];return Endpoint(**native_registers(e,NATIVE_STATE),memory=e.memory.load(NATIVE_STATE+8,4),constraints=tuple(e.solver.constraints))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_equiv()->None:
 i=symbolic_registers("bankswitch_home")
 for x in range(5):i[f"memory{x}"]=claripy.BVS(f"bankswitch_home_mem{x}",8)
 assert_pathwise_equivalent([asm(i)],[native(i)],(*REGISTERS,"memory"))
def test_body()->None:
 loc=symbol_location(SYMBOLS,"BankswitchHome");assert linked_bytes(ROM,loc,17)==bytes.fromhex("ea09cff0b8ea08cffa09cfe0b8ea0020c9")
