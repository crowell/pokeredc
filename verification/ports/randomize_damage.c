#include "port_state.h"

struct randomize_damage_state {
	struct cpu_register_state registers;
	port_u8 damage_high;
};

/* Port of RandomizeDamage through the high-byte zero test. */
__attribute__((noinline, used)) void
port_randomize_damage(struct randomize_damage_state *state)
{
	state->registers.h = 0xd0;
	state->registers.l = 0xd8;
	state->registers.a = state->damage_high;
	state->registers.f = (port_u8)(PORT_FLAG_H |
		((port_u8)(state->damage_high == 0) * PORT_FLAG_Z));
}
