from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddImmediate,Sm83AddRegister,Sm83DecRegister,Sm83IncRegister,Sm83SubImmediate,Sm83SubRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;BOUNDARY=0xefff
CASES=(("MoveTileBlockMapPointerEast","port_move_tile_block_map_pointer_east","1ac60112d0131a3c12c9"),("MoveTileBlockMapPointerWest","port_move_tile_block_map_pointer_west","1ad60112d0131a3d12c9"),("MoveTileBlockMapPointerSouth","port_move_tile_block_map_pointer_south","c606471a8012d0131a3c12c9"),("MoveTileBlockMapPointerNorth","port_move_tile_block_map_pointer_north","c606471a9012d0131a3d12c9"))
class RetNc(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:  # type: ignore[override]
  self.inhibit_autoret=True;self.successors.add_successor(self.state.copy(),BOUNDARY,(self.state.regs.f&1)==0,"Ijk_Boring");self.successors.add_successor(self.state.copy(),self.n,(self.state.regs.f&1)!=0,"Ijk_Boring")
class Done(angr.SimProcedure):
 def run(self)->None:self.jump(BOUNDARY)  # type: ignore[override]
class LoadDe(angr.SimProcedure):
 def __init__(self,n:int,index:int)->None:super().__init__();self.n=n;self.index=index
 def run(self)->None:self.state.regs.a=self.state.globals[f"memory{self.index}"];self.jump(self.n)  # type: ignore[override]
class StoreDe(angr.SimProcedure):
 def __init__(self,n:int,index:int)->None:super().__init__();self.n=n;self.index=index
 def run(self)->None:self.state.globals[f"memory{self.index}"]=self.state.regs.a;self.jump(self.n)  # type: ignore[override]
class IncDe(angr.SimProcedure):
 def __init__(self,n:int)->None:super().__init__();self.n=n
 def run(self)->None:  # type: ignore[override]
  de=claripy.Concat(self.state.regs.d,self.state.regs.e)+1;self.state.regs.d=de[15:8];self.state.regs.e=de[7:0];self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def assembly(symbol:str,i:dict[str,claripy.ast.BV])->list[E]:
 loc=symbol_location(SYMBOLS,symbol);p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loc.address});south=symbol.endswith("South");north=symbol.endswith("North");east=symbol.endswith("East")
 if south or north:p.hook(loc.address,Sm83AddImmediate(6,loc.address+2),length=2)
 arithmetic=loc.address+(4 if south or north else 1)
 if east or south:p.hook(arithmetic,Sm83AddRegister("b",arithmetic+1) if south else Sm83AddImmediate(1,arithmetic+2),length=1 if south else 2)
 else:p.hook(arithmetic,Sm83SubRegister("b",arithmetic+1) if north else Sm83SubImmediate(1,arithmetic+2),length=1 if north else 2)
 load0=loc.address+(3 if south or north else 0);store0=loc.address+(5 if south or north else 3);incde=loc.address+(7 if south or north else 5);load1=incde+1;store1=loc.address+(10 if south or north else 8)
 p.hook(load0,LoadDe(load0+1,0),length=1);p.hook(store0,StoreDe(store0+1,0),length=1);p.hook(incde,IncDe(incde+1),length=1);p.hook(load1,LoadDe(load1+1,1),length=1);p.hook(store1,StoreDe(store1+1,1),length=1)
 ret=loc.address+(6 if south or north else 4);after=ret+1;p.hook(ret,RetNc(after),length=1)
 change=loc.address+(9 if south or north else 7);p.hook(change,(Sm83IncRegister if east or south else Sm83DecRegister)("a",change+1),length=1);p.hook(change+2,Done(),length=1)
 s=p.factory.blank_state(addr=loc.address);set_assembly_registers(s,i);s.globals["memory0"]=i["memory0"];s.globals["memory1"]=i["memory1"];m=p.factory.simulation_manager(s);m.explore(find=BOUNDARY,num_find=2);assert not m.errored and m.found
 return [E(**assembly_registers(x),memory=claripy.Concat(x.globals["memory0"],x.globals["memory1"]),constraints=tuple(x.solver.constraints)) for x in m.found]
def native(c_symbol:str,i:dict[str,claripy.ast.BV])->list[E]:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(c_symbol);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,i["memory0"]);s.memory.store(NATIVE_STATE+9,i["memory1"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored
 return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,2),constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason="native")
@pytest.mark.parametrize("symbol,c_symbol,_body",CASES)
def test_equivalence(symbol:str,c_symbol:str,_body:str)->None:
 i=symbolic_registers(symbol.lower());i["memory0"]=claripy.BVS(f"{symbol}_low",8);i["memory1"]=claripy.BVS(f"{symbol}_high",8);assert_pathwise_equivalent(assembly(symbol,i),native(c_symbol,i),(*REGISTERS,"memory"))
@pytest.mark.parametrize("symbol,_c_symbol,body",CASES)
def test_exact_body(symbol:str,_c_symbol:str,body:str)->None:
 expected=bytes.fromhex(body);assert linked_bytes(ROM,symbol_location(SYMBOLS,symbol),len(expected))==expected
