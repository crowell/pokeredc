#include "port_state.h"

struct handle_building_rage_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
};

/* Port of HandleBuildingRage through the USING_RAGE bit check. */
__attribute__((noinline, used)) void
port_handle_building_rage(struct handle_building_rage_state *state)
{
	state->registers.a = state->whose_turn;
	state->registers.f = (port_u8)(PORT_FLAG_H |
		((port_u8)(state->whose_turn == 0) * PORT_FLAG_Z));
	if (state->whose_turn == 0) {
		state->registers.h = 0xd0;
		state->registers.l = 0x68;
		state->registers.d = 0xcd;
		state->registers.e = 0x2e;
		state->registers.b = 0xcf;
		state->registers.c = 0xcc;
	} else {
		state->registers.h = 0xd0;
		state->registers.l = 0x63;
		state->registers.d = 0xcd;
		state->registers.e = 0x1a;
		state->registers.b = 0xcf;
		state->registers.c = 0xd2;
	}
}
