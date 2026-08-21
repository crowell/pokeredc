#include "port_state.h"

struct read_super_rod_data_private_state {
	struct cpu_register_state registers;
	port_u8 cur_map;
};

/* Port of ReadSuperRodData through IsInArray entry. */
__attribute__((noinline, used)) void
port_read_super_rod_data_private(
	struct read_super_rod_data_private_state *state)
{
	state->registers.a = state->cur_map;
	state->registers.d = 0;
	state->registers.e = 3;
	state->registers.h = 0x69;
	state->registers.l = 0x19;
}
