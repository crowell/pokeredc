from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/"verification/build/ports.elf";ROM=ROOT/"pokered.gbc";SYMBOLS=ROOT/"pokered.sym";NATIVE_STATE=0x100000;DONE=0xEFFF
FIELDS=('money0','money1','money2','price0','price1','price2','text_box_id')
EXPECTED_BODY=bytes.fromhex('1147d3219fff0e03cd8e3ad81149d321a1ff0e033e0ccd6d3e3e13ea25d1cde830')
@dataclass(frozen=True)
class Endpoint:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
 money0:claripy.ast.BV;money1:claripy.ast.BV;money2:claripy.ast.BV;price0:claripy.ast.BV;price1:claripy.ast.BV;price2:claripy.ast.BV;text_box_id:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def bcd_sub(m,p):
 borrow=claripy.BVV(0,8);out=[]
 for i in (2,1,0):
  mo=m[i]&0xf;mt=(m[i]>>4)&0xf;po=p[i]&0xf;pt=(p[i]>>4)&0xf
  bo=mo < po+borrow;ones=claripy.If(bo,mo-po-borrow+10,mo-po-borrow)
  bn=mt < pt+claripy.If(bo,claripy.BVV(1,8),claripy.BVV(0,8));tens=claripy.If(bn,mt-pt-claripy.If(bo,claripy.BVV(1,8),claripy.BVV(0,8))+10,mt-pt-claripy.If(bo,claripy.BVV(1,8),claripy.BVV(0,8)))
  out.insert(0,(tens<<4)|ones);borrow=claripy.If(bn,claripy.BVV(1,8),claripy.BVV(0,8))
 return out
class Summary(angr.SimProcedure):
 def run(self)->None:
  m=[self.state.globals[f'money{i}'] for i in range(3)];p=[self.state.globals[f'price{i}'] for i in range(3)];less=claripy.BoolV(False);eq=claripy.BoolV(True)
  for x,y in zip(m,p):less=claripy.Or(less,claripy.And(eq,x<y));eq=claripy.And(eq,x==y)
  self.inhibit_autoret=True
  fail=self.state.copy();fail.regs.f=claripy.BVV(1,8);self.successors.add_successor(fail,DONE,less,'Ijk_Boring')
  ok=self.state.copy();r=bcd_sub(m,p)
  for i in range(3):ok.globals[f'money{i}']=r[i]
  ok.globals['text_box_id']=claripy.BVV(0x13,8);ok.regs.a=claripy.BVV(0x13,8);ok.regs.f=claripy.BVV(0x10,8);self.successors.add_successor(ok,DONE,claripy.Not(less),'Ijk_Boring')
def _assembly(i):
 l=symbol_location(SYMBOLS,'SubtractAmountPaidFromMoney_');q=l.address;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':q});p.hook(q,Summary(),length=1);s=p.factory.blank_state(addr=q);set_assembly_registers(s,i)
 for f in FIELDS:s.globals[f]=i[f]
 m=p.factory.simulation_manager(s);m.explore(find=DONE,num_find=2);assert len(m.found)==2
 return [Endpoint(**assembly_registers(x),**{f:x.globals[f] for f in FIELDS},constraints=tuple(x.solver.constraints)) for x in m.found]
def _native(i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_subtract_amount_paid_from_money');assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i)
 for off,f in enumerate(FIELDS,8):s.memory.store(NATIVE_STATE+off,i[f])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and m.deadended
 return [Endpoint(**native_registers(x,NATIVE_STATE),**{f:x.memory.load(NATIVE_STATE+off,1) for off,f in enumerate(FIELDS,8)},constraints=tuple(x.solver.constraints)) for x in m.deadended]
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='run native')
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason='run red')
def test_subtract_amount_paid_from_money_pathwise_equivalence():
 i=symbolic_registers('sap');
 for f in FIELDS:i[f]=claripy.BVS('sap_'+f,8)
 assert_pathwise_equivalent(_assembly(i),_native(i),('a','f',*FIELDS))
def test_subtract_amount_paid_from_money_exact_linked_body():
 l=symbol_location(SYMBOLS,'SubtractAmountPaidFromMoney_');assert linked_bytes(ROM,l,len(EXPECTED_BODY))==EXPECTED_BODY
