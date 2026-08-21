#include "port_state.h"

struct link_battle_exchange_state {
	struct cpu_register_state registers;
	port_u8 serial_receive;
	port_u8 player_move_list_index;
};

static port_u8
cp_flags(port_u8 left, port_u8 right)
{
	port_u8 result = (port_u8)(left - right);
	port_u8 flags = PORT_FLAG_N;

	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		flags |= PORT_FLAG_H;
	if (left < right)
		flags |= PORT_FLAG_C;
	return flags;
}

/* Port of LinkBattleExchangeData through the run-command branch. */
__attribute__((noinline, used)) void
port_link_battle_exchange_data(struct link_battle_exchange_state *state)
{
	state->serial_receive = 0xff;
	state->registers.a = state->player_move_list_index;
	state->registers.f = cp_flags(state->registers.a, 0x0f);
}
