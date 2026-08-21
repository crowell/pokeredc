#include "port_state.h"

struct ai_check_hp_fraction_private_state {
	struct cpu_register_state registers;
	port_u8 divisor;
	port_u8 enemy_max_hp_high;
	port_u8 enemy_max_hp_low;
	port_u8 h_divisor;
	port_u8 h_dividend_high;
	port_u8 h_dividend_low;
};

/* Port of AICheckIfHPBelowFraction through Divide setup. */
__attribute__((noinline, used)) void
port_ai_check_if_hp_below_fraction_private(
	struct ai_check_hp_fraction_private_state *state)
{
	state->h_divisor = state->divisor;
	state->h_dividend_high = state->enemy_max_hp_high;
	state->h_dividend_low = state->enemy_max_hp_low;
	state->registers.a = state->enemy_max_hp_low;
	state->registers.b = 2;
	state->registers.h = 0xcf;
	state->registers.l = 0xf5;
}
