#include "port_state.h"

struct update_hp_bar_calc_pixels_private_state {
	struct cpu_register_state registers;
	port_u8 max_low;
	port_u8 max_high;
	port_u8 old_low;
	port_u8 old_high;
	port_u8 new_low;
	port_u8 new_high;
};

/* Port of UpdateHPBar_CalcOldNewHPBarPixels through first GetHPBarLength setup. */
__attribute__((noinline, used)) void
port_update_hp_bar_calc_pixels_private(
	struct update_hp_bar_calc_pixels_private_state *state)
{
	state->registers.e = state->max_low;
	state->registers.d = state->max_high;
	state->registers.c = state->old_low;
	state->registers.b = state->old_high;
	state->registers.l = state->new_low;
	state->registers.h = state->new_high;
}
