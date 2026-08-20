#include "port_state.h"

#define H_WHOSE_TURN 0xfff3u
#define W_CHANGE_MON_PIC_ENEMY_TURN_SPECIES 0xcee9u
#define W_CHANGE_MON_PIC_PLAYER_TURN_SPECIES 0xceea
#define W_CUR_PARTY_SPECIES 0xcf91u
#define W_BATTLE_MON_SPECIES2 0xcfd9u
#define W_CUR_SPECIES 0xd0b5u
#define W_SPRITE_FLIPPED 0xd0aau

/* GetMonHeader is the explicit continuation boundary for both branches. */
__attribute__((noinline, used)) void
port_change_mon_pic(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 whose_turn = memory[H_WHOSE_TURN];

	if (whose_turn != 0) {
		port_u8 species = memory[W_CHANGE_MON_PIC_ENEMY_TURN_SPECIES];
		memory[W_CUR_PARTY_SPECIES] = species;
		memory[W_CUR_SPECIES] = species;
		memory[W_SPRITE_FLIPPED] = 0;
		state->a = 0;
		state->f = PORT_FLAG_Z;
	} else {
		port_u8 species = memory[W_CHANGE_MON_PIC_PLAYER_TURN_SPECIES];
		memory[W_BATTLE_MON_SPECIES2] = species;
		memory[W_CUR_SPECIES] = species;
		state->a = species;
		state->f = (port_u8)(PORT_FLAG_H | PORT_FLAG_Z);
	}
}
