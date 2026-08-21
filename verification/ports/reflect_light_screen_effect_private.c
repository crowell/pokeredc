#include "port_state.h"

struct reflect_light_screen_private_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 player_move_effect;
	port_u8 enemy_move_effect;
};

/* Port of ReflectLightScreenEffect_ through the move-effect load. */
__attribute__((noinline, used)) void
port_reflect_light_screen_effect_private(
	struct reflect_light_screen_private_state *state)
{
	if (state->whose_turn == 0) {
		state->registers.h = 0xd0;
		state->registers.l = 0x64;
		state->registers.d = 0xcf;
		state->registers.e = 0xd3;
		state->registers.a = state->player_move_effect;
	} else {
		state->registers.h = 0xd0;
		state->registers.l = 0x69;
		state->registers.d = 0xcf;
		state->registers.e = 0xcd;
		state->registers.a = state->enemy_move_effect;
	}
	state->registers.f = (port_u8)(PORT_FLAG_H |
		((port_u8)(state->whose_turn == 0) * PORT_FLAG_Z));
}
