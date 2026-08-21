#include "port_state.h"

struct read_trainer_private_state {
	struct cpu_register_state registers;
	port_u8 link_state;
	port_u8 cur_opponent;
	port_u8 enemy_party_count;
	port_u8 enemy_party_species;
};

/* Port of ReadTrainer through party reset and current-opponent load. */
__attribute__((noinline, used)) void
port_read_trainer_private(struct read_trainer_private_state *state)
{
	if (state->link_state != 0)
		return;
	state->enemy_party_count = 0;
	state->enemy_party_species = 0xff;
	state->registers.a = state->cur_opponent;
}
