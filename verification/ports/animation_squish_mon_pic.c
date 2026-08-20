#include "port_state.h"

#define W_SQUISH_MON_CURRENT_DIRECTION 0xd09f

static port_u8
squish_cp_zero(port_u8 value)
{
	return (port_u8)(PORT_FLAG_N | (value == 0 ? PORT_FLAG_Z : 0));
}

/* AnimCopyRowLeft/Right are the explicit continuations for this helper. */
__attribute__((noinline, used)) void
port_animation_squish_mon_pic(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 direction = memory[W_SQUISH_MON_CURRENT_DIRECTION];
	state->c = 3;
	state->a = direction;
	state->f = squish_cp_zero(direction);
}
