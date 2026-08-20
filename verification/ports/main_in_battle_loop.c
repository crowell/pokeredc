#include "port_state.h"

struct main_battle_loop_state {
	struct cpu_register_state registers;
	port_u8 player_hp_low;
	port_u8 player_hp_high;
};

/* Port of MainInBattleLoop through the player-HP fainting branch. */
__attribute__((noinline, used)) void
port_main_in_battle_loop(struct main_battle_loop_state *state)
{
	port_u8 value = state->player_hp_low | state->player_hp_high;

	state->registers.a = value;
	state->registers.f = value == 0 ? PORT_FLAG_Z : 0;
	state->registers.h = 0xd0;
	state->registers.l = 0x16;
}
