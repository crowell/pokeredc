#include "port_state.h"

static __attribute__((noinline)) void
port_sub8(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;
	port_u8 result = left - right;

	registers->a = result;
	registers->f = PORT_FLAG_N;
	if (result == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
}

static __attribute__((noinline)) void
port_sbc8(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;
	port_u8 carry = (registers->f & PORT_FLAG_C) != 0;
	port_u16 subtrahend = (port_u16)right + carry;
	port_u8 result = left - (port_u8)subtrahend;

	registers->a = result;
	registers->f = PORT_FLAG_N;
	if (result == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < ((right & 0x0f) + carry))
		registers->f |= PORT_FLAG_H;
	if ((port_u16)left < subtrahend)
		registers->f |= PORT_FLAG_C;
}

/* Port of UpdateHPBar_CompareNewHPToOldHP in engine/gfx/hp_bar.asm. */
__attribute__((noinline, used)) void
port_update_hp_bar_compare_new_hp_to_old_hp(struct cpu_register_state *registers)
{
	registers->a = registers->d;
	port_sub8(registers, registers->b);
	if (registers->a != 0)
		return;
	registers->a = registers->e;
	port_sub8(registers, registers->c);
}

/* Port of UpdateHPBar_CalcHPDifference in engine/gfx/hp_bar.asm. */
__attribute__((noinline, used)) void
port_update_hp_bar_calc_hp_difference(struct cpu_register_state *registers)
{
	registers->a = registers->d;
	port_sub8(registers, registers->b);
	if (registers->f & PORT_FLAG_C)
		goto old_hp_greater;
	if (registers->f & PORT_FLAG_Z)
		goto test_lower_byte;

new_hp_greater:
	registers->a = registers->e;
	port_sub8(registers, registers->c);
	registers->e = registers->a;
	registers->a = registers->d;
	port_sbc8(registers, registers->b);
	registers->d = registers->a;
	return;

old_hp_greater:
	registers->a = registers->c;
	port_sub8(registers, registers->e);
	registers->e = registers->a;
	registers->a = registers->b;
	port_sbc8(registers, registers->d);
	registers->d = registers->a;
	return;

test_lower_byte:
	registers->a = registers->e;
	port_sub8(registers, registers->c);
	if (registers->f & PORT_FLAG_C)
		goto old_hp_greater;
	if (!(registers->f & PORT_FLAG_Z))
		goto new_hp_greater;
	registers->d = 0;
	registers->e = 0;
}
