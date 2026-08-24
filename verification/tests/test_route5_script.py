from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location

ROOT=Path(__file__).resolve().parents[2]
ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc'
SYMS=ROOT/'pokered.sym'
NS=0x100000;NM=0x400000;STACK=0xD000;RETURN=0xFFFF;DONE=0xEFFF

EXPECTED=linked_bytes(ROM,symbol_location(SYMS,'Route5_Script'),3)

@dataclass(frozen=True)
class E:
    a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV
    d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
    constraints:tuple[claripy.ast.Bool,...]

class ATBDBoundary(angr.SimProcedure):
    """Proven EnableAutoTextBoxDrawing deterministic contract:
    A := $00, F := Z|H, wAutoTextBoxDrawingControl := 0,
    wDoNotWaitForButtonPressAfterDisplayingText := 0."""
    def run(self):
        m=self.state.memory
        self.state.regs.a=claripy.BVV(0x00,8)
        self.state.regs.f=claripy.BVV(0x40,8)
        m.store(0xCF0C,claripy.BVV(0,8));m.store(0xCC3C,claripy.BVV(0,8))
        self.jump(DONE)

class NATB(angr.SimProcedure):
    def run(self):
        s=self.state.regs.rdi
        self.state.globals['at']=self.state.memory.load(s,8)
        self.state.memory.store(s,claripy.Concat(*(self.state.globals[f'at_out_{x}'] for x in REGISTERS)))
        ra=self.state.memory.load(self.state.regs.sp,8,endness='Iend_LE')
        self.state.regs.sp=self.state.regs.sp+8;self.jump(ra)

def inputs(p):
    v=symbolic_registers(p)
    for x in REGISTERS:
        v[f'at_out_{x}']=claripy.Concat(claripy.BVS(f'{p}_at_out_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(f'{p}_at_out_{x}',8)
    return v

def setup(s,v):
    pass

def assembly(v):
    l=symbol_location(SYMS,'Route5_Script')
    assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
    p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,
                   main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),
                              'base_addr':0,'entry_point':l.address})
    t=symbol_location(SYMS,'EnableAutoTextBoxDrawing')
    p.hook(t.address,ATBDBoundary(),length=3)
    s=p.factory.blank_state(addr=l.address)
    set_assembly_registers(s,v);setup(s,v)
    s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
    m=p.factory.simulation_manager(s)
    m.explore(find=DONE,num_find=64)
    assert not m.errored and m.found
    return [E(**assembly_registers(x),constraints=tuple(x.solver.constraints)) for x in m.found]

def native(v):
    p=angr.Project(ELF,auto_load_libs=False)
    f=p.loader.find_symbol('port_route5_script')
    assert f
    s=p.factory.call_state(f.rebased_addr,NS,NM)
    store_native_registers(s,NS,v);setup(s,v)
    m=p.factory.simulation_manager(s);m.run()
    assert not m.errored and m.deadended
    return [E(**native_registers(x,NS),constraints=tuple(x.solver.constraints)) for x in m.deadended]

@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_route5_script_pathwise_equivalence():
    v=inputs('route5_script')
    assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,))
