#include "port_state.h"

struct scale_last_column_private_state {
	struct cpu_register_state registers;
	port_u8 interlace_counter;
};

/* Port of ScaleLastSpriteColumnByTwo through interlace-counter setup. */
__attribute__((noinline, used)) void
port_scale_last_sprite_column_by_two_private(
	struct scale_last_column_private_state *state)
{
	state->registers.a = 0x1c;
	state->registers.b = 0xff;
	state->registers.c = 0xff;
	state->interlace_counter = 0x1c;
}
