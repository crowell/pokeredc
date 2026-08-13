from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83StoreAImmediate

ROOT=Path(__file__).resolve().parents[2]; VERIFY=ROOT/"verification"; NATIVE_ELF=VERIFY/"build"/"ports.elf"; ROM=ROOT/"pokered.gbc"; SYMBOLS=ROOT/"pokered.sym"; NATIVE_STATE=0x100000
PORTS=(("SlotMachine_AnimWheel1","port_slot_machine_anim_wheel1","01e579113ecd2100c33e30ea81d0181e"),("SlotMachine_AnimWheel2","port_slot_machine_anim_wheel2","01097a113fcd2130c33e50ea81d0180e"),("SlotMachine_AnimWheel3","port_slot_machine_anim_wheel3","012d7a1140cd2160c33e70ea81d0"))

@dataclass(frozen=True)
class Endpoint:
    a:claripy.ast.BV; f:claripy.ast.BV; b:claripy.ast.BV; c:claripy.ast.BV; d:claripy.ast.BV; e:claripy.ast.BV; h:claripy.ast.BV; l:claripy.ast.BV
    base_x:claripy.ast.BV; continuation:claripy.ast.BV; constraints:tuple[claripy.ast.Bool,...]

def _assembly(symbol:str,inputs:dict[str,claripy.ast.BV])->Endpoint:
    location=symbol_location(SYMBOLS,symbol); tail=symbol_location(SYMBOLS,"SlotMachine_AnimWheel").address; base_x=symbol_location(SYMBOLS,"wBaseCoordX").address
    project=angr.Project(rom_window(ROM,location.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":location.address})
    project.hook(location.address+11,Sm83StoreAImmediate(base_x,location.address+14),length=3)
    state=project.factory.blank_state(addr=location.address);set_assembly_registers(state,inputs);state.memory.store(base_x,inputs["base_x"])
    manager=project.factory.simulation_manager(state);manager.explore(find=tail);assert not manager.errored and len(manager.found)==1;end=manager.found[0]
    return Endpoint(**assembly_registers(end),base_x=end.memory.load(base_x,1),continuation=claripy.BVV(1,8),constraints=tuple(end.solver.constraints))

def _native(c_symbol:str,inputs:dict[str,claripy.ast.BV])->Endpoint:
    project=angr.Project(NATIVE_ELF,auto_load_libs=False);function=project.loader.find_symbol(c_symbol);assert function
    state=project.factory.call_state(function.rebased_addr,NATIVE_STATE);store_native_registers(state,NATIVE_STATE,inputs);state.memory.store(NATIVE_STATE+8,inputs["base_x"])
    manager=project.factory.simulation_manager(state);manager.run();assert not manager.errored and len(manager.deadended)==1;end=manager.deadended[0]
    return Endpoint(**native_registers(end,NATIVE_STATE),base_x=end.memory.load(NATIVE_STATE+8,1),continuation=claripy.BVV(1,8),constraints=tuple(end.solver.constraints))

@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason="run red")
@pytest.mark.parametrize("symbol,c_symbol,_code",PORTS)
def test_slot_wheel_entry_equivalence(symbol:str,c_symbol:str,_code:str)->None:
    inputs=symbolic_registers(symbol.lower());inputs["base_x"]=claripy.BVS(f"{symbol}_base_x",8)
    assert_pathwise_equivalent([_assembly(symbol,inputs)],[_native(c_symbol,inputs)],(*REGISTERS,"base_x","continuation"))

@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason="run red")
@pytest.mark.parametrize("symbol,_c_symbol,code",PORTS)
def test_slot_wheel_entry_exact_body(symbol:str,_c_symbol:str,code:str)->None:
    expected=bytes.fromhex(code)
    assert linked_bytes(ROM,symbol_location(SYMBOLS,symbol),len(expected)) == expected
