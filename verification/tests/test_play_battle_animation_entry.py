from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];VERIFY=ROOT/"verification";NATIVE_ELF=VERIFY/"build"/"ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;value:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def asm(i:dict[str,claripy.ast.BV])->Endpoint:
 loc=symbol_location(SYMBOLS,"PlayBattleAnimation");tail=symbol_location(SYMBOLS,"PlayBattleAnimationGotID").address;dest=symbol_location(SYMBOLS,"wAnimationID").address;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address,Sm83StoreAImmediate(dest,tail),length=3);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.memory.store(dest,i["value"]);m=p.factory.simulation_manager(s);m.explore(find=tail);assert not m.errored and len(m.found)==1;e=m.found[0];return Endpoint(**assembly_registers(e),value=e.memory.load(dest,1),continuation=claripy.BVV(1,8),constraints=tuple(e.solver.constraints))
def native(i:dict[str,claripy.ast.BV])->Endpoint:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_play_battle_animation");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i["value"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1;e=m.deadended[0];return Endpoint(**native_registers(e,NATIVE_STATE),value=e.memory.load(NATIVE_STATE+8,1),continuation=claripy.BVV(1,8),constraints=tuple(e.solver.constraints))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_equiv()->None:
 i=symbolic_registers("play_battle_animation");i["value"]=claripy.BVS("animation_id",8);assert_pathwise_equivalent([asm(i)],[native(i)],(*REGISTERS,"value","continuation"))
def test_body()->None:
 loc=symbol_location(SYMBOLS,"PlayBattleAnimation");dest=symbol_location(SYMBOLS,"wAnimationID").address;assert linked_bytes(ROM,loc,3)==bytes((0xea,dest&255,dest>>8))

def handle_asm(i:dict[str,claripy.ast.BV])->Endpoint:
 loc=symbol_location(SYMBOLS,"HandleMenuInput");tail=symbol_location(SYMBOLS,"HandleMenuInput_").address;dest=symbol_location(SYMBOLS,"wPartyMenuAnimMonEnabled").address;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address+1,Sm83StoreAImmediate(dest,tail),length=3);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.memory.store(dest,i["value"]);m=p.factory.simulation_manager(s);m.explore(find=tail);assert not m.errored and len(m.found)==1;e=m.found[0];return Endpoint(**assembly_registers(e),value=e.memory.load(dest,1),continuation=claripy.BVV(1,8),constraints=tuple(e.solver.constraints))

def handle_native(i:dict[str,claripy.ast.BV])->Endpoint:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_handle_menu_input");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i["value"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1;e=m.deadended[0];return Endpoint(**native_registers(e,NATIVE_STATE),value=e.memory.load(NATIVE_STATE+8,1),continuation=claripy.BVV(1,8),constraints=tuple(e.solver.constraints))

@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_handle_menu_input_equiv()->None:
 i=symbolic_registers("handle_menu_input");i["value"]=claripy.BVS("party_menu_anim_enabled",8);assert_pathwise_equivalent([handle_asm(i)],[handle_native(i)],(*REGISTERS,"value","continuation"))

def test_handle_menu_input_body()->None:
 loc=symbol_location(SYMBOLS,"HandleMenuInput");dest=symbol_location(SYMBOLS,"wPartyMenuAnimMonEnabled").address;assert linked_bytes(ROM,loc,4)==bytes((0xaf,0xea,dest&255,dest>>8))

def flipped_asm(i:dict[str,claripy.ast.BV])->Endpoint:
 loc=symbol_location(SYMBOLS,"LoadFlippedFrontSpriteByMonIndex");tail=symbol_location(SYMBOLS,"LoadFrontSpriteByMonIndex").address;dest=symbol_location(SYMBOLS,"wSpriteFlipped").address;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address+2,Sm83StoreAImmediate(dest,tail),length=3);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.memory.store(dest,i["value"]);m=p.factory.simulation_manager(s);m.explore(find=tail);assert not m.errored and len(m.found)==1;e=m.found[0];return Endpoint(**assembly_registers(e),value=e.memory.load(dest,1),continuation=claripy.BVV(1,8),constraints=tuple(e.solver.constraints))

def flipped_native(i:dict[str,claripy.ast.BV])->Endpoint:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_load_flipped_front_sprite_by_mon_index");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i["value"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1;e=m.deadended[0];return Endpoint(**native_registers(e,NATIVE_STATE),value=e.memory.load(NATIVE_STATE+8,1),continuation=claripy.BVV(1,8),constraints=tuple(e.solver.constraints))

@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_flipped_sprite_entry_equiv()->None:
 i=symbolic_registers("flipped_sprite_entry");i["value"]=claripy.BVS("sprite_flipped",8);assert_pathwise_equivalent([flipped_asm(i)],[flipped_native(i)],(*REGISTERS,"value","continuation"))
def test_flipped_sprite_entry_body()->None:
 loc=symbol_location(SYMBOLS,"LoadFlippedFrontSpriteByMonIndex");dest=symbol_location(SYMBOLS,"wSpriteFlipped").address;assert linked_bytes(ROM,loc,5)==bytes((0x3e,1,0xea,dest&255,dest>>8))
