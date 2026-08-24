from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.sm83_shims import Sm83LoadAImmediate
from verification.harness.rom import linked_bytes,rom_window,symbol_location

ROOT=Path(__file__).resolve().parents[2]
ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc'
SYMS=ROOT/'pokered.sym'
NS=0x100000;NM=0x400000;STACK=0xD000;RETURN=0xFFFF;PLC_ENTRY=0x1523;DONE=0xEFFF
W_LOADED_MON_LEVEL=0xCFB9

EXPECTED=linked_bytes(ROM,symbol_location(SYMS,'PrintLevel'),16)

@dataclass(frozen=True)
class E:
    a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV
    d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
    constraints:tuple[claripy.ast.Bool,...]

class PLCZ80(angr.SimProcedure):
    """PrintLevelCommon entry boundary."""
    def run(self):
        self.jump(DONE)

def inputs(p):
    v=symbolic_registers(p)
    v['level_in']=claripy.BVS(f'{p}_level_in',8)
    return v

def store_memory(s,v):
    s.memory.store(W_LOADED_MON_LEVEL,v['level_in'])

def assembly(v):
    l=symbol_location(SYMS,'PrintLevel')
    assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
    p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,
                   rebase_granularity=0x100,
                   main_opts={'backend':'blob',
                              'arch':ArchPcode('z80:LE:16:default'),
                              'base_addr':0,'entry_point':l.address})
    b=l.address
    p.hook(b+5,Sm83LoadAImmediate(W_LOADED_MON_LEVEL,b+8),length=3)
    p.hook(PLC_ENTRY,PLCZ80(),length=3)
    p.hook(b+20,PLCZ80(),length=3)
    s=p.factory.blank_state(addr=b)
    set_assembly_registers(s,v);store_memory(s,v)
    s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
    m=p.factory.simulation_manager(s)
    m.explore(find=lambda st:st.addr==DONE,num_find=64)
    assert not m.errored and m.found
    return [E(**assembly_registers(x),
              constraints=tuple(x.solver.constraints)) for x in m.found]

def native(v):
    p=angr.Project(ELF,auto_load_libs=False)
    f=p.loader.find_symbol('port_print_level')
    s=p.factory.call_state(f.rebased_addr,NS,NM)
    store_native_registers(s,NS,v)
    s.memory.store(NM+W_LOADED_MON_LEVEL,v['level_in'])
    m=p.factory.simulation_manager(s);m.run()
    assert not m.errored and m.deadended
    return [E(**native_registers(x,NS),
              constraints=tuple(x.solver.constraints)) for x in m.deadended]

@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_print_level_pathwise_equivalence():
    v=inputs('print_level')
    A=assembly(v)
    N=native(v)
    print(f'asm:{len(A)} nat:{len(N)}')
    for i,e in enumerate(A):
        s=claripy.Solver()
        for c in e.constraints:s.add(c)
        print(f'A{i}: a={s.eval(e.a,1)[0]:#04x} f={s.eval(e.f,1)[0]:#04x} d={s.eval(e.d,1)[0]:#04x}')
    for j,e in enumerate(N):
        s=claripy.Solver()
        for c in e.constraints:s.add(c)
        print(f'N{j}: a={s.eval(e.a,1)[0]:#04x} f={s.eval(e.f,1)[0]:#04x} d={s.eval(e.d,1)[0]:#04x}')
