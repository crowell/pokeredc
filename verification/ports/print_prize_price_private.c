#include "port_state.h"

struct print_prize_price_private_state {
	struct cpu_register_state registers;
};

/* Port of PrintPrizePrice through price-box setup. */
__attribute__((noinline, used)) void
port_print_prize_price_private(struct print_prize_price_private_state *state)
{
	state->registers.h = 0xc3;
	state->registers.l = 0xab;
	state->registers.b = 1;
	state->registers.c = 7;
}
