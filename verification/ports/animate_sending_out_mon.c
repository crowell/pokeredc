#include "port_state.h"

struct animate_sending_out_mon_state {
	struct cpu_register_state registers;
	port_u8 predef_hl_low;
	port_u8 predef_hl_high;
	port_u8 start_tile_id;
	port_u8 is_in_battle;
};

/* Port of AnimateSendingOutMon through the in-battle branch. */
__attribute__((noinline, used)) void
port_animate_sending_out_mon(struct animate_sending_out_mon_state *state)
{
	state->registers.h = state->predef_hl_high;
	state->registers.l = state->predef_hl_low;
	state->registers.b = 0x4c;
	state->registers.a = state->is_in_battle;
	state->registers.f = (port_u8)(PORT_FLAG_H |
		((port_u8)(state->is_in_battle == 0) * PORT_FLAG_Z));
}
