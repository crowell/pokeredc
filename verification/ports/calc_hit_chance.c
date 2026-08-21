#include "port_state.h"

struct calc_hit_chance_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 player_move_accuracy;
	port_u8 enemy_move_accuracy;
	port_u8 player_accuracy_mod;
	port_u8 enemy_evasion_mod;
	port_u8 enemy_accuracy_mod;
	port_u8 player_evasion_mod;
};

/* Port of CalcHitChance through the reflected evasion setup. */
__attribute__((noinline, used)) void
port_calc_hit_chance(struct calc_hit_chance_state *state)
{
	port_u8 evasion;
	if (state->whose_turn == 0) {
		state->registers.h = 0xcf;
		state->registers.l = 0xd6;
		state->registers.b = state->player_accuracy_mod;
		evasion = state->enemy_evasion_mod;
	} else {
		state->registers.h = 0xcf;
		state->registers.l = 0xd0;
		state->registers.b = state->enemy_accuracy_mod;
		evasion = state->player_evasion_mod;
	}
	state->registers.c = (port_u8)(0x0e - evasion);
	state->registers.a = state->registers.c;
	state->registers.f = (port_u8)(PORT_FLAG_N |
		((port_u8)(state->registers.c == 0) * PORT_FLAG_Z) |
		((port_u8)((evasion & 0x0f) > 0x0e) * PORT_FLAG_H) |
		((port_u8)(evasion > 0x0e) * PORT_FLAG_C));
}
