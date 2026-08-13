from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83DecRegister

ROOT=Path(__file__).resolve().parents[2];VERIFY=ROOT/"verification";NATIVE_ELF=VERIFY/"build"/"ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;LOOP=0xeffe;RETURN=0xefff

class StoreOnce(angr.SimProcedure):
    def __init__(self,next_address:int)->None:super().__init__();self.next=next_address
    def run(self)->None:  # type: ignore[override]
        if self.state.globals.get("entered",False):self.jump(LOOP);return
        self.state.globals["entered"]=True;self.state.globals["written"]=self.state.regs.a;self.state.regs.hl=self.state.regs.hl+1;self.jump(self.next)
class Boundary(angr.SimProcedure):
    def __init__(self,address:int)->None:super().__init__();self.address=address
    def run(self)->None:self.jump(self.address)  # type: ignore[override]
@dataclass(frozen=True)
class Endpoint:
    a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;written:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]

def native(sym:str,inputs:dict[str,claripy.ast.BV])->list[Endpoint]:
    p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,inputs);s.memory.store(NATIVE_STATE+8,inputs["written"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored
    return [Endpoint(**native_registers(e,NATIVE_STATE),written=e.memory.load(NATIVE_STATE+8,1),continuation=claripy.If(e.regs.rax[7:0]==0,claripy.BVV(1,8),claripy.BVV(0,8)),constraints=tuple(e.solver.constraints)) for e in m.deadended]

def begin(inputs:dict[str,claripy.ast.BV])->Endpoint:
    loc=symbol_location(SYMBOLS,"ClearSprites");p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address+6,Boundary(LOOP),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,inputs);m=p.factory.simulation_manager(s);m.explore(find=LOOP);assert not m.errored and len(m.found)==1;e=m.found[0];return Endpoint(**assembly_registers(e),written=inputs["written"],continuation=claripy.BVV(1,8),constraints=tuple(e.solver.constraints))

def step(inputs:dict[str,claripy.ast.BV])->list[Endpoint]:
    loc=symbol_location(SYMBOLS,"ClearSprites");loop=loc.address+6;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loop});p.hook(loop,StoreOnce(loop+1),length=1);p.hook(loop+1,Sm83DecRegister("b",loop+2),length=1);p.hook(loop+4,Boundary(RETURN),length=1);s=p.factory.blank_state(addr=loop);set_assembly_registers(s,inputs);s.globals["written"]=inputs["written"];m=p.factory.simulation_manager(s);m.stashes["found"]=[]
    while m.active:
        m.move(from_stash="active",to_stash="found",filter_func=lambda x:x.addr in {LOOP,RETURN})
        if m.active:m.step()
    assert not m.errored;return [Endpoint(**assembly_registers(e),written=e.globals["written"],continuation=claripy.BVV(1 if e.addr==LOOP else 0,8),constraints=tuple(e.solver.constraints)) for e in m.found]

@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_clear_sprites_begin()->None:
    i=symbolic_registers("clear_sprites_begin");i["written"]=claripy.BVS("clear_begin_written",8);assert_pathwise_equivalent([begin(i)],native("port_clear_sprites_begin",i),(*REGISTERS,"continuation"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_clear_sprites_step()->None:
    i=symbolic_registers("clear_sprites_step");i["written"]=claripy.BVS("clear_step_written",8);assert_pathwise_equivalent(step(i),native("port_clear_sprites_step",i),(*REGISTERS,"written","continuation"))
def test_clear_sprites_body()->None:
    loc=symbol_location(SYMBOLS,"ClearSprites");assert linked_bytes(ROM,loc,11)==bytes.fromhex("af2100c306a0220520fcc9")
