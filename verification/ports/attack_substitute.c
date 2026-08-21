#include "port_state.h"

struct attack_substitute_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
};

extern void port_print_text(struct cpu_register_state *state, port_u8 *memory);
static port_u8 substitute_text_memory[0x10000];

/* Port of AttackSubstitute through the damage-to-substitute branch. */
__attribute__((noinline, used)) void
port_attack_substitute(struct attack_substitute_state *state)
{
	state->registers.h = 0x62;
	state->registers.l = 0xac;
	port_print_text(&state->registers, substitute_text_memory);
	state->registers.a = state->whose_turn;
	state->registers.f = (port_u8)(PORT_FLAG_H |
		((port_u8)(state->whose_turn == 0) * PORT_FLAG_Z));
	if (state->whose_turn == 0) {
		state->registers.d = 0xcc;
		state->registers.e = 0xd8;
		state->registers.b = 0xd0;
		state->registers.c = 0x68;
	} else {
		state->registers.d = 0xcc;
		state->registers.e = 0xd7;
		state->registers.b = 0xd0;
		state->registers.c = 0x63;
	}
}
