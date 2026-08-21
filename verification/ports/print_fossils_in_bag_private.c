#include "port_state.h"

struct print_fossils_private_state {
	struct cpu_register_state registers;
	port_u8 item_counter;
};

/* Port of PrintFossilsInBag through filtered-list loop setup. */
__attribute__((noinline, used)) void
port_print_fossils_in_bag_private(struct print_fossils_private_state *state)
{
	state->registers.h = 0xcc;
	state->registers.l = 0x5b;
	state->registers.a = 0;
	state->registers.f = 0;
	state->item_counter = 0;
}
