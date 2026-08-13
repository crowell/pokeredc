#include "port_state.h"

static void
flag_logic(struct cpu_register_state *registers, port_u8 result, port_u8 half)
{
	registers->a = result;
	registers->f = half ? PORT_FLAG_H : 0;
	if (result == 0)
		registers->f |= PORT_FLAG_Z;
}

static void
flag_action(struct flag_action_state *state)
{
	port_u8 original_b = state->registers.b;
	port_u8 original_c = state->registers.c;
	port_u8 original_d = state->registers.d;
	port_u8 original_e = state->registers.e;
	port_u8 original_h = state->registers.h;
	port_u8 original_l = state->registers.l;
	port_u8 mask = (port_u8)(1u << (original_c & 7));
	port_u8 result;

	if (original_b == 0) {
		result = (port_u8)(state->value & (port_u8)~mask);
		state->value = result;
		flag_logic(&state->registers, result, 1);
	} else if (original_b == 2) {
		result = (port_u8)(state->value & mask);
		flag_logic(&state->registers, result, 1);
	} else {
		result = (port_u8)(state->value | mask);
		state->value = result;
		flag_logic(&state->registers, result, 0);
	}
	state->registers.b = original_b;
	state->registers.c = result;
	state->registers.d = original_d;
	state->registers.e = original_e;
	state->registers.h = original_h;
	state->registers.l = original_l;
}

/* Ports of the identical FlagAction implementations. */
__attribute__((noinline, used)) void
port_flag_action(struct flag_action_state *state)
{
	flag_action(state);
}

__attribute__((noinline, used)) void
port_toggleable_object_flag_action(struct flag_action_state *state)
{
	flag_action(state);
}
