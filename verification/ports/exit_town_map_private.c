#include "port_state.h"

struct exit_town_map_private_state {
	struct cpu_register_state registers;
	port_u8 sprite_blinking_enabled;
};

/* Port of ExitTownMap through GBPalWhiteOut entry. */
__attribute__((noinline, used)) void
port_exit_town_map_private(struct exit_town_map_private_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->sprite_blinking_enabled = 0;
}
