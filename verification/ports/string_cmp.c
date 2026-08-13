#include "port_state.h"

static port_u8
compare_flags(port_u8 left, port_u8 right)
{
	port_u8 flags = PORT_FLAG_N;

	if (left == right)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		flags |= PORT_FLAG_H;
	if (left < right)
		flags |= PORT_FLAG_C;

	return flags;
}

/* Port of StringCmp in home/compare.asm. */
__attribute__((noinline, used)) port_u8
port_string_cmp_step(
	struct string_cmp_state *state, port_u8 left, port_u8 right)
{
	port_u8 previous_c;

	state->a = left;
	state->f = compare_flags(state->a, right);
	if ((state->f & PORT_FLAG_Z) == 0)
		return 1;

	state->de++;
	state->hl++;
	previous_c = state->c;
	state->c--;
	state->f = (state->f & PORT_FLAG_C) | PORT_FLAG_N;
	if (state->c == 0)
		state->f |= PORT_FLAG_Z;
	if ((previous_c & 0x0f) == 0)
		state->f |= PORT_FLAG_H;
	return state->c == 0;
}

__attribute__((noinline, used)) void
port_string_cmp(struct string_cmp_state *state, const port_u8 *memory)
{
	while (!port_string_cmp_step(
		state, memory[state->de], memory[state->hl]))
		;
}
