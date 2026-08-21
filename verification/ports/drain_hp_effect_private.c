#include "port_state.h"

struct drain_hp_private_state {
	struct cpu_register_state registers;
	port_u8 damage_high;
};

/* Port of DrainHPEffect_ through the first damage shift. */
__attribute__((noinline, used)) void
port_drain_hp_effect_private(struct drain_hp_private_state *state)
{
	port_u8 old = state->damage_high;
	state->registers.h = 0xd0;
	state->registers.l = 0xd7;
	state->registers.a = (port_u8)(old >> 1);
	state->registers.f = (port_u8)(((port_u8)(state->registers.a == 0) * PORT_FLAG_Z) |
		((port_u8)(old & 1) * PORT_FLAG_C));
}
