#include "port_state.h"

struct divide_bcd_get_next_digit_private_state {
	struct cpu_register_state registers;
};

/* Port of DivideBCD_getNextDigit through first StringCmp entry. */
__attribute__((noinline, used)) void
port_divide_bcd_get_next_digit_private(
	struct divide_bcd_get_next_digit_private_state *state)
{
	state->registers.b = 0;
	state->registers.c = 3;
}
