#include "port_state.h"

struct call_current_trade_center_function_private_state {
	struct cpu_register_state registers;
};

/* Port of CallCurrentTradeCenterFunction through pointer-index load. */
__attribute__((noinline, used)) void
port_call_current_trade_center_function_private(
	struct call_current_trade_center_function_private_state *state)
{
	state->registers.h = 0x5a;
	state->registers.l = 0x5b;
	state->registers.b = 0;
}
