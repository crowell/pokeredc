from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83DecRegister,Sm83SubRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";STACK=0xd000;RETURN=0xffff;NATIVE_STATE=0x100000
class Fetch(angr.SimProcedure):
 def __init__(self,n,index):super().__init__();self.n=n;self.index=index
 def run(self):self.state.regs.a=self.state.globals["fetched"][self.index];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;fetched:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(i):
 loc=symbol_location(SYMBOLS,"GetTextBoxIDCoords");p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address})
 for index,offset in enumerate((0,2,4,8)):p.hook(loc.address+offset,Fetch(loc.address+offset+1,index),length=1)
 p.hook(loc.address+5,Sm83SubRegister("e",loc.address+6),length=1);p.hook(loc.address+6,Sm83DecRegister("a",loc.address+7),length=1);p.hook(loc.address+9,Sm83SubRegister("d",loc.address+10),length=1);p.hook(loc.address+10,Sm83DecRegister("a",loc.address+11),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.globals["fetched"]=[i[f"fetched{n}"] for n in range(4)];s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness="Iend_LE");ends=collect_returns(p,s,RETURN);return [E(**assembly_registers(x),fetched=claripy.Concat(*(i[f"fetched{n}"] for n in range(4))),constraints=tuple(x.solver.constraints)) for x in ends]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_get_text_box_id_coords");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for n in range(4):s.memory.store(NATIVE_STATE+8+n,i[f"fetched{n}"])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),fetched=claripy.Concat(*(x.memory.load(NATIVE_STATE+8+n,1) for n in range(4))),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_equivalence():
 i=symbolic_registers("text_box_coords")
 for n in range(4):i[f"fetched{n}"]=claripy.BVS(f"text_box_coords_fetched{n}",8)
 assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,"fetched"))
def test_body():
 loc=symbol_location(SYMBOLS,"GetTextBoxIDCoords");assert linked_bytes(ROM,loc,13)==bytes.fromhex("2a5f2a572a933d4f2a923d47c9")
