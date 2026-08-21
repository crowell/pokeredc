#include "port_state.h"

struct transform_private_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 enemy_status1;
	port_u8 player_status1;
};

/* Port of TransformEffect_ through the INVULNERABLE bit-test setup. */
__attribute__((noinline, used)) void
port_transform_effect_private(struct transform_private_state *state)
{
	state->registers.f = (port_u8)(PORT_FLAG_H |
		((port_u8)(state->whose_turn == 0) * PORT_FLAG_Z));
	if (state->whose_turn == 0) {
		state->registers.h = 0xcf;
		state->registers.l = 0xe5;
		state->registers.d = 0xd0;
		state->registers.e = 0x14;
		state->registers.b = 0xd0;
		state->registers.c = 0x64;
		state->registers.a = state->player_status1;
	} else {
		state->registers.h = 0xd0;
		state->registers.l = 0x14;
		state->registers.d = 0xcf;
		state->registers.e = 0xe5;
		state->registers.b = 0xd0;
		state->registers.c = 0x69;
		state->registers.a = state->whose_turn;
	}
}
