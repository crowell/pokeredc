#include "port_state.h"

enum item_id {
	ITEM_HM01 = 0xc4,
	ITEM_TM01 = 0xc9,
};

static port_u8
comparison_flags(port_u8 left, port_u8 right)
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

/* Port of IsItemHM in home/names.asm. */
__attribute__((noinline, used)) void
port_is_item_hm(struct accumulator_state *state)
{
	if (state->a < ITEM_HM01) {
		/* AND A clears carry and sets H; A itself is unchanged. */
		state->f = PORT_FLAG_H;
		if (state->a == 0)
			state->f |= PORT_FLAG_Z;
		return;
	}

	state->f = comparison_flags(state->a, ITEM_TM01);
}
