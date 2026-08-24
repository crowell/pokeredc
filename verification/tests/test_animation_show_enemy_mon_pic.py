from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,sm83_flags_to_z80,symbol_location

ROOT=Path(__file__).resolve().parents[2]
ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc'
SYMS=ROOT/'pokered.sym'
NS=0x100000;NM=0x400000;STACK=0xD000;RETURN=0xFFFF;DONE=0xEFFF

EXPECTED=linked_bytes(ROM,symbol_location(SYMS,'AnimationShowEnemyMonPic'),6)

@dataclass(frozen=True)
class E:
    a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV
    d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
    cwt:claripy.ast.BV
    constraints:tuple[claripy.ast.Bool,...]

class CWTFBoundary(angr.SimProcedure):
    """Proven CallWithTurnFlipped boundary at the tail target."""
    def run(self):
        r=assembly_registers(self.state)
        self.state.globals['cwt']=claripy.Concat(*(r[x] for x in REGISTERS))
        for x in REGISTERS:
            v=self.state.globals['cwt_out_'+x]
            setattr(self.state.regs,x,sm83_flags_to_z80(v) if x=='f' else v)
        self.jump(DONE)

class NCWT(angr.SimProcedure):
    def run(self):
        s=self.state.regs.rdi
        self.state.globals['cwt']=self.state.memory.load(s,8)
        self.state.memory.store(s,claripy.Concat(*(self.state.globals[f'cwt_out_{x}'] for x in REGISTERS)))
        ra=self.state.memory.load(self.state.regs.sp,8,endness='Iend_LE')
        self.state.regs.sp=self.state.regs.sp+8;self.jump(ra)

def inputs(p):
    v=symbolic_registers(p)
    for x in REGISTERS:
        v[f'cwt_out_{x}']=claripy.Concat(claripy.BVS(f'{p}_cwt_out_flags',4),claripy.BVV(0,4)) if x=='f' else claripy.BVS(f'{p}_cwt_out_{x}',8)
    return v

def setup(s,v):
    s.globals['cwt']=claripy.BVV(0,8*8)
    for key,val in v.items():
        if key.startswith('cwt_out_'):s.globals[key]=val

def assembly(v):
    l=symbol_location(SYMS,'AnimationShowEnemyMonPic')
    assert linked_bytes(ROM,l,len(EXPECTED))==EXPECTED
    p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,
                   main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),
                              'base_addr':0,'entry_point':l.address})
    t=symbol_location(SYMS,'CallWithTurnFlipped')
    p.hook(t.address,CWTFBoundary())
    s=p.factory.blank_state(addr=l.address)
    set_assembly_registers(s,v);setup(s,v)
    s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
    m=p.factory.simulation_manager(s)
    m.explore(find=DONE,num_find=64)
    assert not m.errored and m.found
    return [E(**assembly_registers(x),cwt=x.globals['cwt'],
              constraints=tuple(x.solver.constraints)) for x in m.found]

def native(v):
    p=angr.Project(ELF,auto_load_libs=False)
    f=p.loader.find_symbol('port_animation_show_enemy_mon_pic')
    t=p.loader.find_symbol('port_call_with_turn_flipped')
    assert f and t
    p.hook(t.rebased_addr,NCWT())
    s=p.factory.call_state(f.rebased_addr,NS)
    store_native_registers(s,NS,v);setup(s,v)
    m=p.factory.simulation_manager(s);m.run()
    assert not m.errored and m.deadended
    return [E(**native_registers(x,NS),cwt=x.globals['cwt'],
              constraints=tuple(x.solver.constraints)) for x in m.deadended]

@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_animation_show_enemy_mon_pic_pathwise_equivalence():
    v=inputs('animation_show_enemy_mon_pic')
    assert_pathwise_equivalent(assembly(v),native(v),(*REGISTERS,'cwt'))
