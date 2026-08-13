#include "port_state.h"

static void
table_add_a(struct cpu_register_state *registers)
{
	port_u8 value = registers->a;
	port_u16 result = (port_u16)value + value;

	registers->a = (port_u8)result;
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((value & 0x0f) + (value & 0x0f) > 0x0f)
		registers->f |= PORT_FLAG_H;
	if (result > 0xff)
		registers->f |= PORT_FLAG_C;
}

static void
table_add_hl(struct cpu_register_state *registers, port_u16 right)
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
port_call_function_in_table_begin(struct call_function_table_state *state)
{
	port_u16 hl;

	state->saved_h = state->registers.h;
	state->saved_l = state->registers.l;
	state->saved_d = state->registers.d;
	state->saved_e = state->registers.e;
	state->saved_b = state->registers.b;
	state->saved_c = state->registers.c;
	table_add_a(&state->registers);
	state->registers.d = 0;
	state->registers.e = state->registers.a;
	table_add_hl(&state->registers, state->registers.e);
	state->registers.a = state->fetched_low;
	hl = (port_u16)(((port_u16)state->registers.h << 8) | state->registers.l);
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.h = state->fetched_high;
	state->registers.l = state->registers.a;
	state->registers.d = 0x3d;
	state->registers.e = 0xa7;
}

__attribute__((noinline, used)) void
port_call_function_in_table_return(struct call_function_table_state *state)
{
	state->registers.b = state->saved_b;
	state->registers.c = state->saved_c;
	state->registers.d = state->saved_d;
	state->registers.e = state->saved_e;
	state->registers.h = state->saved_h;
	state->registers.l = state->saved_l;
}

/* Port of CallFunctionInTable in home/array2.asm. */
__attribute__((noinline, used)) void
port_call_function_in_table(struct call_function_table_state *state,
	port_u8 callback_a, port_u8 callback_f)
{
	port_call_function_in_table_begin(state);
	/* The indirect target is an explicit compositional boundary. */
	state->registers.a = callback_a;
	state->registers.f = callback_f;
	port_call_function_in_table_return(state);
}
