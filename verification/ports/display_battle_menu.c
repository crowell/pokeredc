#include "port_state.h"

struct display_battle_menu_state {
	struct cpu_register_state registers;
	port_u8 battle_type;
};

/* Port of DisplayBattleMenu through its standard/nonstandard battle branch. */
__attribute__((noinline, used)) void
port_display_battle_menu(struct display_battle_menu_state *state)
{
	state->registers.a = state->battle_type;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
}
