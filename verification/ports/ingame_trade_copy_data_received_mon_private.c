#include "port_state.h"

struct ingame_trade_copy_received_private_state {
	struct cpu_register_state registers;
};

/* Port of InGameTrade_CopyDataToReceivedMon through first pointer setup. */
__attribute__((noinline, used)) void
port_ingame_trade_copy_data_received_mon_private(
	struct ingame_trade_copy_received_private_state *state)
{
	state->registers.h = 0xd2;
	state->registers.l = 0xb5;
	state->registers.b = 0;
	state->registers.c = 0x0b;
}
