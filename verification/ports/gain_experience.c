#include "port_state.h"

struct gain_experience_state {
	struct cpu_register_state registers;
	port_u8 link_state;
};

/* Port of GainExperience through the link-battle early return. */
__attribute__((noinline, used)) void
port_gain_experience(struct gain_experience_state *state)
{
	port_u8 value = state->link_state;
	state->registers.a = value;
	state->registers.f = (port_u8)(PORT_FLAG_N |
		((port_u8)((value & 0x0f) < 4) * PORT_FLAG_H) |
		((port_u8)(value < 4) * PORT_FLAG_C) |
		((port_u8)(value == 4) * PORT_FLAG_Z));
}
