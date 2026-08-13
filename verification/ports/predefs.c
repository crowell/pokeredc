#include "port_state.h"

static void
predef_add_a(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;
	port_u16 result = (port_u16)left + right;

	registers->a = (port_u8)result;
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) > 0x0f)
		registers->f |= PORT_FLAG_H;
	if (result > 0xff)
		registers->f |= PORT_FLAG_C;
}

static void
predef_add_hl(struct cpu_register_state *registers, port_u16 right)
{
	port_u16 left = (port_u16)(((port_u16)registers->h << 8) | registers->l);
	unsigned long result = (unsigned long)left + right;

	registers->f &= PORT_FLAG_Z;
	if ((left & 0x0fff) + (right & 0x0fff) > 0x0fff)
		registers->f |= PORT_FLAG_H;
	if (result > 0xffff)
		registers->f |= PORT_FLAG_C;
	registers->h = (port_u8)(result >> 8);
	registers->l = (port_u8)result;
}

/* Port of GetPredefPointer in engine/predefs.asm. */
__attribute__((noinline, used)) void
port_get_predef_pointer(struct predef_pointer_state *state)
{
	port_u16 de;
	port_u8 old_d;
	port_u8 original_id;

	state->registers.a = state->registers.h;
	state->saved_h = state->registers.a;
	state->registers.a = state->registers.l;
	state->saved_l = state->registers.a;
	state->registers.h = 0xcc;
	state->registers.l = 0x51;
	state->registers.a = state->registers.d;
	state->saved_d = state->registers.a;
	state->registers.l++;
	state->registers.a = state->registers.e;
	state->saved_e = state->registers.a;
	state->registers.l++;
	state->registers.a = state->registers.b;
	state->saved_b = state->registers.a;
	state->registers.l++;
	state->saved_c = state->registers.c;
	state->registers.h = 0x7e;
	state->registers.l = 0x79;
	state->registers.d = 0;
	state->registers.e = 0;
	state->registers.a = state->predef_id;
	state->registers.e = state->registers.a;
	original_id = state->registers.e;
	predef_add_a(&state->registers, state->registers.a);
	predef_add_a(&state->registers, original_id);
	state->registers.e = state->registers.a;
	if ((state->registers.f & PORT_FLAG_C) != 0) {
		old_d = state->registers.d;
		state->registers.d++;
		state->registers.f &= PORT_FLAG_C;
		if (state->registers.d == 0)
			state->registers.f |= PORT_FLAG_Z;
		if ((old_d & 0x0f) == 0x0f)
			state->registers.f |= PORT_FLAG_H;
	}
	de = (port_u16)(((port_u16)state->registers.d << 8) | state->registers.e);
	predef_add_hl(&state->registers, de);
	state->registers.d = state->registers.h;
	state->registers.e = state->registers.l;
	de = (port_u16)(((port_u16)state->registers.d << 8) | state->registers.e);
	state->registers.a = state->fetched_bank;
	state->predef_bank = state->registers.a;
	de++;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	state->registers.a = state->fetched_pointer_low;
	state->registers.l = state->registers.a;
	de++;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	state->registers.a = state->fetched_pointer_high;
	state->registers.h = state->registers.a;
}
