from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AdcRegister,Sm83DecRegister,Sm83SrlRegister,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;BOUNDARY=0xefff
class Bound(angr.SimProcedure):
 def run(self):self.jump(BOUNDARY)  # type: ignore[override]
class Fetch(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.a=self.state.globals["fetched"];self.state.regs.hl=self.state.regs.hl+1;self.jump(self.n)  # type: ignore[override]
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;result:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def project(loc):return angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address})
def ep(x,i,result=0):return E(**assembly_registers(x),memory=claripy.Concat(x.memory.load(symbol_location(SYMBOLS,"wNumSetBits").address,1),i["fetched"]),result=claripy.BVV(result,8),constraints=tuple(x.solver.constraints))
def native(sym,i,ret=False):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(sym);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i["output"]);s.memory.store(NATIVE_STATE+9,i["fetched"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=claripy.Concat(x.memory.load(NATIVE_STATE+8,1),x.memory.load(NATIVE_STATE+9,1)),result=(x.regs.rax[7:0] if ret else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
def state_at(loc,i,address):
 s=project(loc).factory.blank_state(addr=address);set_assembly_registers(s,i);s.memory.store(symbol_location(SYMBOLS,"wNumSetBits").address,i["output"]);return s
def begin(i):
 loc=symbol_location(SYMBOLS,"CountSetBits");p=project(loc);p.hook(loc.address+2,Bound(),length=1);s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.memory.store(symbol_location(SYMBOLS,"wNumSetBits").address,i["output"]);m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);return ep(m.found[0],i)
def outer_begin(i):
 loc=symbol_location(SYMBOLS,"CountSetBits");p=project(loc);p.hook(loc.address+2,Fetch(loc.address+3),length=1);p.hook(loc.address+6,Bound(),length=1);s=p.factory.blank_state(addr=loc.address+2);set_assembly_registers(s,i);s.memory.store(symbol_location(SYMBOLS,"wNumSetBits").address,i["output"]);s.globals["fetched"]=i["fetched"];m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);return ep(m.found[0],i)
def inner(i):
 loc=symbol_location(SYMBOLS,"CountSetBits");p=project(loc);start=loc.address+6;p.hook(start,Sm83SrlRegister("e",start+2),length=2);p.hook(start+4,Sm83AdcRegister("c",start+5),length=1);p.hook(start+6,Sm83DecRegister("d",start+7),length=1);p.hook(start+7,Bound(),length=2);s=p.factory.blank_state(addr=start);set_assembly_registers(s,i);s.memory.store(symbol_location(SYMBOLS,"wNumSetBits").address,i["output"]);m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);x=m.found[0];base=dict(assembly_registers(x));constraints=tuple(x.solver.constraints);mem=claripy.Concat(x.memory.load(symbol_location(SYMBOLS,"wNumSetBits").address,1),i["fetched"]);return [E(**base,memory=mem,result=claripy.BVV(1,8),constraints=constraints+(base["d"]==0,)),E(**base,memory=mem,result=claripy.BVV(0,8),constraints=constraints+(base["d"]!=0,))]
def outer_finish(i):
 loc=symbol_location(SYMBOLS,"CountSetBits");p=project(loc);start=loc.address+15;p.hook(start,Sm83DecRegister("b",start+1),length=1);p.hook(start+1,Bound(),length=2);s=p.factory.blank_state(addr=start);set_assembly_registers(s,i);s.memory.store(symbol_location(SYMBOLS,"wNumSetBits").address,i["output"]);m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);x=m.found[0];base=dict(assembly_registers(x));constraints=tuple(x.solver.constraints);mem=claripy.Concat(x.memory.load(symbol_location(SYMBOLS,"wNumSetBits").address,1),i["fetched"]);return [E(**base,memory=mem,result=claripy.BVV(1,8),constraints=constraints+(base["b"]==0,)),E(**base,memory=mem,result=claripy.BVV(0,8),constraints=constraints+(base["b"]!=0,))]
def finish(i):
 loc=symbol_location(SYMBOLS,"CountSetBits");out=symbol_location(SYMBOLS,"wNumSetBits").address;p=project(loc);p.hook(loc.address+19,Sm83StoreAImmediate(out,BOUNDARY),length=3);s=p.factory.blank_state(addr=loc.address+18);set_assembly_registers(s,i);s.memory.store(out,i["output"]);m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY);return ep(m.found[0],i)
def inputs(prefix):
 i=symbolic_registers(prefix);i["output"]=claripy.BVS(prefix+"_output",8);i["fetched"]=claripy.BVS(prefix+"_fetched",8);return i
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
@pytest.mark.parametrize("phase,port",[(begin,"port_count_set_bits_begin"),(outer_begin,"port_count_set_bits_outer_begin"),(finish,"port_count_set_bits_finish")])
def test_fixed_phases(phase,port):
 i=inputs(port);assert_pathwise_equivalent([phase(i)],native(port,i),(*REGISTERS,"memory"))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
@pytest.mark.parametrize("phase,port",[(inner,"port_count_set_bits_inner_step"),(outer_finish,"port_count_set_bits_outer_finish")])
def test_recurrences(phase,port):
 i=inputs(port);assert_pathwise_equivalent(phase(i),native(port,i,True),(*REGISTERS,"memory","result"))
def test_body():
 loc=symbol_location(SYMBOLS,"CountSetBits");assert linked_bytes(ROM,loc,23)==bytes.fromhex("0e002a5f1608cb3b3e00894f1520f70520f079ea1ed1c9")
