#include "port_state.h"

struct battle_health_bar_color_state {
	struct cpu_register_state registers;
	port_u8 current_color;
};

/* Port of GetBattleHealthBarColor through GetHealthBarColor. */
__attribute__((noinline, used)) void
port_get_battle_health_bar_color(struct battle_health_bar_color_state *state)
{
	state->registers.b = state->current_color;
}
