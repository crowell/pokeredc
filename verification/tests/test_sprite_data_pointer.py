from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83LoadAHighImmediate,Sm83SwapRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";STACK=0xd000;RETURN=0xffff;NATIVE_STATE=0x100000
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;value:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(i:dict[str,claripy.ast.BV])->E:
 loc=symbol_location(SYMBOLS,"GetSpriteDataPointer");src=symbol_location(SYMBOLS,"hSpriteIndex").address;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address+1,Sm83AddHlRegisterPair("de",loc.address+2),length=1);p.hook(loc.address+2,Sm83LoadAHighImmediate(src,loc.address+4),length=2);p.hook(loc.address+4,Sm83SwapRegister("a",loc.address+6),length=2);p.hook(loc.address+9,Sm83AddHlRegisterPair("de",loc.address+10),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.memory.store(src,i["value"]);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness="Iend_LE");ends=collect_returns(p,s,RETURN);assert len(ends)==1;x=ends[0];return E(**assembly_registers(x),value=x.memory.load(src,1),constraints=tuple(x.solver.constraints))
def native(i:dict[str,claripy.ast.BV])->E:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_get_sprite_data_pointer");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i["value"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1;x=m.deadended[0];return E(**native_registers(x,NATIVE_STATE),value=x.memory.load(NATIVE_STATE+8,1),constraints=tuple(x.solver.constraints))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_equivalence()->None:
 i=symbolic_registers("sprite_data_pointer");i["value"]=claripy.BVS("sprite_data_index",8);assert_pathwise_equivalent([assembly(i)],[native(i)],(*REGISTERS,"value"))
def test_body()->None:
 loc=symbol_location(SYMBOLS,"GetSpriteDataPointer");src=symbol_location(SYMBOLS,"hSpriteIndex").address;expected=bytes((0xd5,0x19,0xf0,src&0xff))+bytes.fromhex("cb3716005f19d1c9");assert linked_bytes(ROM,loc,len(expected))==expected
