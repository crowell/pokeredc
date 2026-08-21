#include "port_state.h"

struct scale_first_three_private_state {
	struct cpu_register_state registers;
};

/* Port of ScaleFirstThreeSpriteColumnsByTwo through its loop setup. */
__attribute__((noinline, used)) void
port_scale_first_three_sprite_columns_by_two_private(
	struct scale_first_three_private_state *state)
{
	state->registers.b = 0x03;
	state->registers.c = 0x1c;
}
