#include "port_state.h"

struct pick_up_item_private_state {
	struct cpu_register_state registers;
	port_u8 sprite_index;
};

/* Port of PickUpItem through sprite-index setup. */
__attribute__((noinline, used)) void
port_pick_up_item_private(struct pick_up_item_private_state *state)
{
	state->registers.a = state->sprite_index;
	state->registers.b = state->sprite_index;
}
