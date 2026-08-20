#include "port_state.h"

struct remove_fainted_player_state {
	struct cpu_register_state registers;
	port_u8 player_mon_number;
};

/* Port of RemoveFaintedPlayerMon through the first FlagActionPredef call. */
__attribute__((noinline, used)) void
port_remove_fainted_player_mon(struct remove_fainted_player_state *state)
{
	state->registers.a = state->player_mon_number;
	state->registers.c = state->registers.a;
	state->registers.b = 0;
	state->registers.h = 0xd0;
	state->registers.l = 0x58;
}
