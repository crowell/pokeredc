from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import linked_bytes, rom_window, sm83_flags_to_z80, symbol_location
from verification.harness.sm83_shims import Sm83BitRegister

ROOT=Path(__file__).resolve().parents[2]; NATIVE_ELF=ROOT/'verification/build/ports.elf'; ROM=ROOT/'pokered.gbc'; SYMBOLS=ROOT/'pokered.sym'
NATIVE_STATE=0x100000; NATIVE_MEMORY=0x200000; DONE=0xefff; MARKER=0x1234
EXPECTED=bytes.fromhex('f040cb7f200e2188621100960100023e04c3f717118862210096012004c34818')
FIELDS=('requested_bank','loaded_bank','rom_bank','lcd_control')

@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV; f:claripy.ast.BV; b:claripy.ast.BV; c:claripy.ast.BV; d:claripy.ast.BV; e:claripy.ast.BV; h:claripy.ast.BV; l:claripy.ast.BV
 memory:claripy.ast.BV; call_registers:claripy.ast.BV; kind:claripy.ast.BV; marker:claripy.ast.BV; constraints:tuple[claripy.ast.Bool,...]

class LoadLcdc(angr.SimProcedure):
 def __init__(self,n:int): super().__init__(); self.n=n
 def run(self)->None: self.state.regs.a=self.state.globals['lcd_control']; self.jump(self.n)  # type: ignore[override]

class TransferSummary(angr.SimProcedure):
 def __init__(self,kind:int,banked:bool): super().__init__(); self.kind=kind; self.banked=banked
 def run(self)->None:  # type: ignore[override]
  call=assembly_registers(self.state); self.state.globals['call_registers']=claripy.Concat(*(call[r] for r in REGISTERS)); self.state.globals['kind']=claripy.BVV(self.kind,8)
  for r in REGISTERS:
   v=self.state.globals[f'callee_{r}']; setattr(self.state.regs,r,sm83_flags_to_z80(v) if r=='f' else v)
  if self.banked:
   for field in FIELDS[:3]: self.state.globals[field]=self.state.globals[f'callee_{field}']
  self.state.memory.store(MARKER,self.state.globals['callee_marker']); self.jump(DONE)

class NativeTransferSummary(angr.SimProcedure):
 def __init__(self,kind:int,banked:bool): super().__init__(); self.kind=kind; self.banked=banked
 def run(self,state:claripy.ast.BV,memory:claripy.ast.BV)->None:  # type: ignore[override]
  self.state.globals['call_registers']=self.state.memory.load(state,8); self.state.globals['kind']=claripy.BVV(self.kind,8)
  for i,r in enumerate(REGISTERS): self.state.memory.store(state+i,self.state.globals[f'callee_{r}'])
  if self.banked:
   for i,field in enumerate(FIELDS[:3],8): self.state.memory.store(state+i,self.state.globals[f'callee_{field}'])
  self.state.memory.store(memory+MARKER,self.state.globals['callee_marker'])

def inputs(p:str)->dict[str,claripy.ast.BV]:
 v=symbolic_registers(p)
 for f in FIELDS: v[f]=claripy.BVS(f'{p}_{f}',8)
 for r in REGISTERS: v[f'callee_{r}']=claripy.Concat(claripy.BVS(f'{p}_callee_flags',4),claripy.BVV(0,4)) if r=='f' else claripy.BVS(f'{p}_callee_{r}',8)
 for f in FIELDS[:3]: v[f'callee_{f}']=claripy.BVS(f'{p}_callee_{f}',8)
 v['marker']=claripy.BVS(f'{p}_marker',8); v['callee_marker']=claripy.BVS(f'{p}_callee_marker',8); return v

def setup_globals(s:angr.SimState,v:dict[str,claripy.ast.BV])->None:
 for f in FIELDS: s.globals[f]=v[f]
 for r in REGISTERS: s.globals[f'callee_{r}']=v[f'callee_{r}']
 for f in FIELDS[:3]: s.globals[f'callee_{f}']=v[f'callee_{f}']
 s.globals['callee_marker']=v['callee_marker']; s.globals['call_registers']=claripy.BVV(0,64); s.globals['kind']=claripy.BVV(0,8)

def assembly(v:dict[str,claripy.ast.BV])->list[Endpoint]:
 loc=symbol_location(SYMBOLS,'LoadTextBoxTilePatterns'); assert linked_bytes(ROM,loc,len(EXPECTED))==EXPECTED
 p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':loc.address}); q=loc.address
 p.hook(q,LoadLcdc(q+2),length=2); p.hook(q+2,Sm83BitRegister(7,'a',q+4),length=2); p.hook(q+17,TransferSummary(1,True),length=3); p.hook(q+20,TransferSummary(2,False),length=12)
 s=p.factory.blank_state(addr=q); set_assembly_registers(s,v); setup_globals(s,v); s.memory.store(MARKER,v['marker']); m=p.factory.simulation_manager(s); m.explore(find=DONE,num_find=10)
 return [Endpoint(**assembly_registers(x),memory=claripy.Concat(*(x.globals[f] for f in FIELDS)),call_registers=x.globals['call_registers'],kind=x.globals['kind'],marker=x.memory.load(MARKER,1),constraints=tuple(x.solver.constraints)) for x in m.found]

def native(v:dict[str,claripy.ast.BV])->list[Endpoint]:
 p=angr.Project(NATIVE_ELF,auto_load_libs=False); fn=p.loader.find_symbol('port_load_text_box_tile_patterns'); far=p.loader.find_symbol('port_far_copy_data2'); on=p.loader.find_symbol('port_load_text_box_tile_patterns_on'); assert fn and far and on
 p.hook(far.rebased_addr,NativeTransferSummary(1,True)); p.hook(on.rebased_addr,NativeTransferSummary(2,False)); s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE,NATIVE_MEMORY); store_native_registers(s,NATIVE_STATE,v)
 for i,f in enumerate(FIELDS,8): s.memory.store(NATIVE_STATE+i,v[f])
 setup_globals(s,v); s.memory.store(NATIVE_MEMORY+MARKER,v['marker']); m=p.factory.simulation_manager(s); m.run(); assert not m.errored
 return [Endpoint(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(FIELDS)),call_registers=x.globals['call_registers'],kind=x.globals['kind'],marker=x.memory.load(NATIVE_MEMORY+MARKER,1),constraints=tuple(x.solver.constraints)) for x in m.deadended]

@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run `make red`')
def test_load_text_box_tile_patterns_pathwise_equivalence()->None:
 v=inputs('load_text_box_tile_patterns'); assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'memory','call_registers','kind','marker'))
