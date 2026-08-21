#include "port_state.h"

struct do_ingame_trade_dialogue_private_state {
	struct cpu_register_state registers;
	port_u8 which_trade;
};

/* Port of DoInGameTradeDialogue through trade-index setup. */
__attribute__((noinline, used)) void
port_do_ingame_trade_dialogue_private(
	struct do_ingame_trade_dialogue_private_state *state)
{
	state->registers.a = state->which_trade;
	state->registers.b = state->which_trade;
}
