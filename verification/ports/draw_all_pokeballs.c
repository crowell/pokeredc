#include "port_state.h"

struct draw_all_pokeballs_state {
	struct cpu_register_state registers;
	port_u8 is_in_battle;
};

/* Port of DrawAllPokeballs through the wild-battle return check. */
__attribute__((noinline, used)) void
port_draw_all_pokeballs(struct draw_all_pokeballs_state *state)
{
	port_u8 old = state->is_in_battle;
	port_u8 result = (port_u8)(old - 1);
	state->registers.a = result;
	state->registers.f = (state->registers.f & PORT_FLAG_C) | PORT_FLAG_N |
		((port_u8)((old & 0x0f) == 0) * PORT_FLAG_H) |
		((port_u8)(result == 0) * PORT_FLAG_Z);
}
