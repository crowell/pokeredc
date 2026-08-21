#include "port_state.h"

struct read_player_mon_cur_hp_state {
	struct cpu_register_state registers;
	port_u8 player_mon_number;
};

/* Port of ReadPlayerMonCurHPAndStatus through its AddNTimes call. */
__attribute__((noinline, used)) void
port_read_player_mon_cur_hp_status(struct read_player_mon_cur_hp_state *state)
{
	state->registers.a = state->player_mon_number;
	state->registers.b = 0;
	state->registers.c = 0x2c;
	state->registers.h = 0xd1;
	state->registers.l = 0x6c;
}
