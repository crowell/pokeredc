#include "port_state.h"

static port_u8
subtraction_flags(port_u8 left, port_u8 right, port_u8 result)
{
	port_u8 flags = PORT_FLAG_N;

	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		flags |= PORT_FLAG_H;
	if (left < right)
		flags |= PORT_FLAG_C;
	return flags;
}

/* Port of CalcDifference in home/pathfinding.asm. */
__attribute__((noinline, used)) void
port_calc_difference(struct binary_accumulator_state *state)
{
	port_u8 left = state->a;
	port_u8 result = (port_u8)(left - state->b);

	state->a = result;
	state->f = subtraction_flags(left, state->b, result);
	if (left < state->b) {
		state->a = (port_u8)(~result + 1);
		state->f = PORT_FLAG_C;
	}
}

/* Port of CompareHLWithBC in engine/overworld/update_map.asm. */
__attribute__((noinline, used)) void
port_compare_hl_with_bc(struct cpu_register_state *state)
{
	port_u8 left = state->h;
	port_u8 result;

	state->a = left;
	result = (port_u8)(left - state->b);
	state->a = result;
	state->f = subtraction_flags(left, state->b, result);
	if (result != 0)
		return;

	left = state->l;
	state->a = left;
	result = (port_u8)(left - state->c);
	state->a = result;
	state->f = subtraction_flags(left, state->c, result);
}
