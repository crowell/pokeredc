#include "port_state.h"

struct print_bookshelf_private_state {
	struct cpu_register_state registers;
	port_u8 facing_direction;
	port_u8 map_tileset;
	port_u8 interacted_bookshelf;
};

/* Port of PrintBookshelfText through facing/map-tileset dispatch setup. */
__attribute__((noinline, used)) void
port_print_bookshelf_text_private(struct print_bookshelf_private_state *state)
{
	if (state->facing_direction == 4) {
		state->registers.a = state->map_tileset;
		return;
	}
	state->registers.a = state->facing_direction;
	state->interacted_bookshelf = 0xff;
}
