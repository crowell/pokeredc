#include "port_state.h"

struct update_hp_bar_print_hp_number_private_state {
	struct cpu_register_state registers;
	port_u8 hp_bar_type;
};

/* Port of UpdateHPBar_PrintHPNumber through enemy-HUD guard. */
__attribute__((noinline, used)) void
port_update_hp_bar_print_hp_number_private(
	struct update_hp_bar_print_hp_number_private_state *state)
{
	state->registers.a = state->hp_bar_type;
	state->registers.f = 0;
}
