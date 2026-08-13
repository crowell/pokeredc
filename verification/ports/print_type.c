#include "port_state.h"

static void
type_add_a(struct cpu_register_state *registers)
{
	port_u8 left = registers->a;
	port_u16 result = (port_u16)left + left;

	registers->a = (port_u8)result;
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (left & 0x0f) > 0x0f)
		registers->f |= PORT_FLAG_H;
	if (result > 0xff)
		registers->f |= PORT_FLAG_C;
}

static void
type_add_hl(struct cpu_register_state *registers, port_u16 right)
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

__attribute__((noinline, used)) void
port_print_type_begin(struct print_type_state *state)
{
	port_u16 hl;

	state->saved_h = state->registers.h;
	state->saved_l = state->registers.l;
	type_add_a(&state->registers);
	state->registers.h = 0x7d;
	state->registers.l = 0xae;
	state->registers.e = state->registers.a;
	state->registers.d = 0;
	type_add_hl(&state->registers, state->registers.e);
	state->registers.a = state->fetched_low;
	hl = (port_u16)(((port_u16)state->registers.h << 8) | state->registers.l);
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.e = state->registers.a;
	state->registers.d = state->fetched_high;
	state->registers.h = state->saved_h;
	state->registers.l = state->saved_l;
	state->dispatched = 1;
}

/* Port of PrintType in engine/battle/print_type.asm. */
__attribute__((noinline, used)) void
port_print_type(struct print_type_state *state,
	const struct cpu_register_state *callback_registers)
{
	port_print_type_begin(state);
	/* The JP to PlaceString is an explicit tail-continuation boundary. */
	state->registers = *callback_registers;
}
