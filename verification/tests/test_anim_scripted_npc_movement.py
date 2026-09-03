from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    REGISTERS, assembly_registers, native_registers, set_assembly_registers,
    store_native_registers, symbolic_registers,
)
from verification.harness.rom import linked_bytes, rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NS, NM, STACK, RET = 0x100000, 0x200000, 0xd000, 0xffff
S1, S2, OFFSET, SLOT, FRAME = 0xc100, 0xc200, 0xffda, 0xffe9, 0xffea
BODY = bytes.fromhex("2100c2f0dac60e6f7e3dcb37472100c1f0dac6096f7efe00280dfe042809fe082805fe0c2801c98047e0e9cd01532100c1f0dac6026ff0e947f0ea8077c9")


@dataclass(frozen=True)
class E:
    a: claripy.ast.BV; f: claripy.ast.BV; b: claripy.ast.BV; c: claripy.ast.BV
    d: claripy.ast.BV; e: claripy.ast.BV; h: claripy.ast.BV; l: claripy.ast.BV
    state: claripy.ast.BV; constraints: tuple[claripy.ast.Bool, ...]


class Pair(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None: super().__init__(); self.value=value; self.next_address=next_address
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h=claripy.BVV(self.value>>8,8); self.state.regs.l=claripy.BVV(self.value&0xff,8); self.jump(self.next_address)


class LoadHigh(angr.SimProcedure):
    def __init__(self, address: int, next_address: int) -> None: super().__init__(); self.address=address; self.next_address=next_address
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a=self.state.memory.load(self.address,1); self.jump(self.next_address)


class Reg(angr.SimProcedure):
    def __init__(self, destination: str, source: str, next_address: int) -> None: super().__init__(); self.destination=destination; self.source=source; self.next_address=next_address
    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs,self.destination,getattr(self.state.regs,self.source)); self.jump(self.next_address)


class LoadAtHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None: super().__init__(); self.next_address=next_address
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a=self.state.memory.load(self.state.regs.hl,1); self.jump(self.next_address)


class StoreAtHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None: super().__init__(); self.next_address=next_address
    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl,self.state.regs.a); self.jump(self.next_address)


class StoreHighA(angr.SimProcedure):
    def __init__(self, address: int, next_address: int) -> None: super().__init__(); self.address=address; self.next_address=next_address
    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.address,self.state.regs.a); self.jump(self.next_address)


class AddA(angr.SimProcedure):
    def __init__(self, value: int | str, next_address: int) -> None: super().__init__(); self.value=value; self.next_address=next_address
    def run(self) -> None:  # type: ignore[override]
        left=self.state.regs.a; right=getattr(self.state.regs,self.value) if isinstance(self.value,str) else claripy.BVV(self.value,8)
        wide=claripy.ZeroExt(1,left)+claripy.ZeroExt(1,right); self.state.regs.a=wide[7:0]
        self.state.regs.f=claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If((left&15)+(right&15)>15,claripy.BVV(0x10,8),claripy.BVV(0,8))|claripy.ZeroExt(7,wide[8]); self.jump(self.next_address)


class DecA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None: super().__init__(); self.next_address=next_address
    def run(self) -> None:  # type: ignore[override]
        old=self.state.regs.a; self.state.regs.a=old-1; self.state.regs.f=(self.state.regs.f&1)|2|claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If((old&15)==0,claripy.BVV(0x10,8),claripy.BVV(0,8)); self.jump(self.next_address)


class SwapA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None: super().__init__(); self.next_address=next_address
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a=(self.state.regs.a<<4)|claripy.LShR(self.state.regs.a,4); self.state.regs.f=claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8)); self.jump(self.next_address)


class CpBranch(angr.SimProcedure):
    def __init__(self, value: int, taken: int, fallthrough: int) -> None: super().__init__(); self.value=value; self.taken=taken; self.fallthrough=fallthrough
    def run(self) -> None:  # type: ignore[override]
        left=self.state.regs.a; right=claripy.BVV(self.value,8)
        self.state.regs.f=claripy.BVV(2,8)|claripy.If(left==right,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If((left&15).ULT(right&15),claripy.BVV(0x10,8),claripy.BVV(0,8))|claripy.If(left.ULT(right),claripy.BVV(1,8),claripy.BVV(0,8))
        condition=(self.state.regs.f&0x40)!=0; yes=self.state.copy(); no=self.state.copy(); yes.solver.add(condition); no.solver.add(~condition); yes.regs.ip=claripy.BVV(self.taken,16); no.regs.ip=claripy.BVV(self.fallthrough,16); self.inhibit_autoret=True; self.successors.add_successor(yes,self.taken,condition,"Ijk_Boring"); self.successors.add_successor(no,self.fallthrough,~condition,"Ijk_Boring")


class Return(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        target=self.state.memory.load(self.state.regs.sp,2,endness="Iend_LE"); self.state.regs.sp+=2; self.jump(target)


class AdvanceBoundary(angr.SimProcedure):
    """Complete separately-proven AdvanceScriptedNPCAnimFrameCounter transition."""
    def __init__(self, next_address: int) -> None: super().__init__(); self.next_address=next_address
    def run(self) -> None:  # type: ignore[override]
        offset=self.state.memory.load(OFFSET,1); self.state.regs.a=offset+7; self.state.regs.l=self.state.regs.a
        old=self.state.memory.load(self.state.regs.hl,1); self.state.regs.a=old+1; self.state.memory.store(self.state.regs.hl,self.state.regs.a)
        result=self.state.regs.a-4; self.state.regs.f=claripy.BVV(2,8)|claripy.If(result==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If((self.state.regs.a&15).ULT(4),claripy.BVV(0x10,8),claripy.BVV(0,8))|claripy.If(self.state.regs.a.ULT(4),claripy.BVV(1,8),claripy.BVV(0,8))
        rollover=self.state.regs.a==4; done=self.state.copy(); again=self.state.copy(); done.solver.add(~rollover); again.solver.add(rollover)
        done.regs.ip=claripy.BVV(self.next_address,16); again.memory.store(again.regs.hl,claripy.BVV(0,8)); again.regs.l+=1; again.regs.a=again.memory.load(again.regs.hl,1)+1; again.regs.a=again.regs.a&3; again.regs.f=claripy.If(again.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8)); again.memory.store(again.regs.hl,again.regs.a); again.memory.store(FRAME,again.regs.a); again.regs.ip=claripy.BVV(self.next_address,16); self.inhibit_autoret=True; self.successors.add_successor(done,self.next_address,~rollover,"Ijk_Boring"); self.successors.add_successor(again,self.next_address,rollover,"Ijk_Boring")


def setup(state: angr.SimState, base: int, facing: int, values: dict[str, claripy.ast.BV]) -> None:
    for address in (*range(S1,S1+16),*range(S2,S2+16)): state.memory.store(base+address,claripy.BVV(0,8))
    state.memory.store(base+OFFSET,claripy.BVV(0,8)); state.memory.store(base+S2+14,values["vram_slot"]); state.memory.store(base+S1+9,claripy.BVV(facing,8)); state.memory.store(base+S1+7,values["intra"]); state.memory.store(base+S1+8,values["frame"]); state.memory.store(base+S1+2,values["image"]); state.memory.store(base+SLOT,values["slot_and_facing"]); state.memory.store(base+FRAME,values["output"])


def endpoint(state: angr.SimState, native: bool) -> E:
    base=NM if native else 0; registers=native_registers(state,NS) if native else assembly_registers(state); watched=(*range(S1,S1+16),*range(S2,S2+16),OFFSET,SLOT,FRAME); return E(**registers,state=claripy.Concat(*(state.memory.load(base+x,1) for x in watched)),constraints=tuple(state.solver.constraints))


def assembly(values: dict[str,claripy.ast.BV], facing: int) -> list[E]:
    location=symbol_location(SYMBOLS,"AnimScriptedNPCMovement"); assert linked_bytes(ROM,location,len(BODY))==BODY
    project=angr.Project(rom_window(ROM,location.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":location.address}); q=location.address
    project.hook(q,Pair(0xc200,q+3),length=3); project.hook(q+3,LoadHigh(OFFSET,q+5),length=2); project.hook(q+5,AddA(14,q+7),length=2); project.hook(q+7,Reg("l","a",q+8),length=1); project.hook(q+8,LoadAtHL(q+9),length=1); project.hook(q+9,DecA(q+10),length=1); project.hook(q+10,SwapA(q+12),length=2); project.hook(q+12,Reg("b","a",q+13),length=1); project.hook(q+13,Pair(0xc100,q+16),length=3); project.hook(q+16,LoadHigh(OFFSET,q+18),length=2); project.hook(q+18,AddA(9,q+20),length=2); project.hook(q+20,Reg("l","a",q+21),length=1); project.hook(q+21,LoadAtHL(q+22),length=1)
    project.hook(q+22,CpBranch(0,q+39,q+26),length=4); project.hook(q+26,CpBranch(4,q+39,q+30),length=4); project.hook(q+30,CpBranch(8,q+39,q+34),length=4); project.hook(q+34,CpBranch(12,q+39,q+38),length=4); project.hook(q+38,Return(),length=1); project.hook(q+39,AddA("b",q+40),length=1); project.hook(q+40,Reg("b","a",q+41),length=1); project.hook(q+41,StoreHighA(SLOT,q+43),length=2); project.hook(q+43,AdvanceBoundary(q+46),length=3); project.hook(q+46,Pair(0xc100,q+49),length=3); project.hook(q+49,LoadHigh(OFFSET,q+51),length=2); project.hook(q+51,AddA(2,q+53),length=2); project.hook(q+53,Reg("l","a",q+54),length=1); project.hook(q+54,LoadHigh(SLOT,q+56),length=2); project.hook(q+56,Reg("b","a",q+57),length=1); project.hook(q+57,LoadHigh(FRAME,q+59),length=2); project.hook(q+59,AddA("b",q+60),length=1); project.hook(q+60,StoreAtHL(q+61),length=1); project.hook(q+61,Return(),length=1)
    state=project.factory.blank_state(addr=q); set_assembly_registers(state,values); setup(state,0,facing,values); state.regs.sp=claripy.BVV(STACK,16); state.memory.store(STACK,claripy.BVV(RET,16),endness="Iend_LE"); manager=project.factory.simulation_manager(state); manager.explore(find=RET,num_find=4); assert not manager.errored and manager.found; return [endpoint(x,False) for x in manager.found]


def native(values: dict[str,claripy.ast.BV], facing: int) -> list[E]:
    project=angr.Project(ELF,auto_load_libs=False); function=project.loader.find_symbol("port_anim_scripted_npc_movement"); assert function is not None; state=project.factory.call_state(function.rebased_addr,NS,NM); store_native_registers(state,NS,values); setup(state,NM,facing,values); manager=project.factory.simulation_manager(state); manager.run(); assert not manager.errored and manager.deadended; return [endpoint(x,True) for x in manager.deadended]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),reason="build artifacts missing")
@pytest.mark.parametrize("facing",[0,4,8,12,1])
def test_anim_scripted_npc_movement_pathwise_equivalence(facing: int) -> None:
    values=symbolic_registers("anim_scripted_npc")
    for field in ("vram_slot","intra","frame","image","slot_and_facing","output"):
        values[field]=claripy.BVS(f"anim_scripted_npc_{field}",8)
    assert_pathwise_equivalent(assembly(values,facing),native(values,facing),(*REGISTERS,"state"))
