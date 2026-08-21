#include "port_state.h"

struct print_card_key_text_private_state {
	struct cpu_register_state registers;
	port_u8 cur_map;
};

/* Port of PrintCardKeyText through initial map-list setup. */
__attribute__((noinline, used)) void
port_print_card_key_text_private(struct print_card_key_text_private_state *state)
{
	state->registers.h = 0x66;
	state->registers.l = 0xe3;
	state->registers.a = state->cur_map;
	state->registers.b = state->cur_map;
}
