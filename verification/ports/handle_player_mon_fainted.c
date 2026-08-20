#include "port_state.h"

struct handle_player_fainted_state {
	struct cpu_register_state registers;
	port_u8 in_handle_player_mon_fainted;
};

/* Port of HandlePlayerMonFainted setup through RemoveFaintedPlayerMon. */
__attribute__((noinline, used)) void
port_handle_player_mon_fainted(struct handle_player_fainted_state *state)
{
	state->registers.a = 1;
	state->in_handle_player_mon_fainted = state->registers.a;
}
