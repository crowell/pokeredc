from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import collect_returns,linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate,Sm83LoadAImmediate,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";STACK=0xd000;RETURN=0xffff;NATIVE_STATE=0x100000
NAMES=("wInitListType","wNameListType","wListPointer","wListPointer","wUnusedNamePointer","wUnusedNamePointer","wItemPrices","wItemPrices")
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def addresses():
 base={name:symbol_location(SYMBOLS,name).address for name in set(NAMES)};return (base["wInitListType"],base["wNameListType"],base["wListPointer"],base["wListPointer"]+1,base["wUnusedNamePointer"],base["wUnusedNamePointer"]+1,base["wItemPrices"],base["wItemPrices"]+1)
def assembly(i):
 loc=symbol_location(SYMBOLS,"InitList");a=addresses();p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});p.hook(loc.address,Sm83LoadAImmediate(a[0],loc.address+3),length=3)
 for offset,value in ((3,1),(17,4),(31,5),(45,2)):p.hook(loc.address+offset,Sm83CpImmediate(value,loc.address+offset+2),length=2)
 for offset,index in ((67,1),(71,2),(75,3),(79,4),(83,5),(90,6),(94,7)):p.hook(loc.address+offset,Sm83StoreAImmediate(a[index],loc.address+offset+3),length=3)
 s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i)
 for n,address in enumerate(a):s.memory.store(address,i[f"memory{n}"])
 s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness="Iend_LE");ends=collect_returns(p,s,RETURN);return [E(**assembly_registers(x),memory=claripy.Concat(*(x.memory.load(v,1) for v in a)),constraints=tuple(x.solver.constraints)) for x in ends]
def native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_init_list");assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for n in range(8):s.memory.store(NATIVE_STATE+8+n,i[f"memory{n}"])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=claripy.Concat(*(x.memory.load(NATIVE_STATE+8+n,1) for n in range(8))),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
def test_equivalence():
 i=symbolic_registers("init_list")
 for n in range(8):i[f"memory{n}"]=claripy.BVS(f"init_list_memory{n}",8)
 assert_pathwise_equivalent(assembly(i),native(i),(*REGISTERS,"memory"))
def test_body():
 loc=symbol_location(SYMBOLS,"InitList");assert linked_bytes(ROM,loc,98)==bytes.fromhex("fa1bd1fe01200a219cd811acd93e061832fe04200a2163d11173d23e051824fe05200a217bcf111e423e011816fe02200a211dd3112b473e041808217bcf112b473e04eab6d07dea8bcf7cea8ccf7bea8dcf7aea8ecf01084679ea8fcf78ea90cfc9")
