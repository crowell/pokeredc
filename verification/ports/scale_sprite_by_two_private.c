#include "port_state.h"

struct scale_sprite_by_two_private_state {
	struct cpu_register_state registers;
};

/* Port of ScaleSpriteByTwo through the first column-scaling call boundary. */
__attribute__((noinline, used)) void
port_scale_sprite_by_two_private(struct scale_sprite_by_two_private_state *state)
{
	state->registers.d = 0xa2;
	state->registers.e = 0x03;
	state->registers.h = 0xa1;
	state->registers.l = 0x87;
}
