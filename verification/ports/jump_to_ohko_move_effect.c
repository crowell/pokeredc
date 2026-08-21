#include "port_state.h"

struct jump_to_ohko_state {
	struct cpu_register_state registers;
	port_u8 move_missed;
};

/* Port of JumpToOHKOMoveEffect after the JumpMoveEffect boundary. */
__attribute__((noinline, used)) void
port_jump_to_ohko_move_effect(struct jump_to_ohko_state *state)
{
	port_u8 value = state->move_missed;
	port_u8 carry = state->registers.f & PORT_FLAG_C;
	port_u8 result = (port_u8)(value - 1);
	state->registers.a = result;
	state->registers.f = (port_u8)(carry | PORT_FLAG_N |
		((port_u8)((value & 0x0f) == 0) * PORT_FLAG_H) |
		((port_u8)(result == 0) * PORT_FLAG_Z));
}
