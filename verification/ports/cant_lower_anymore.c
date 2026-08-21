#include "port_state.h"

struct cant_lower_anymore_state {
	struct cpu_register_state registers;
	port_u8 move_effect;
};

/* Port of CantLowerAnymore through the stat-lowering threshold check. */
__attribute__((noinline, used)) void
port_cant_lower_anymore(struct cant_lower_anymore_state *state)
{
	port_u8 value = state->move_effect;
	state->registers.a = value;
	state->registers.f = (port_u8)(PORT_FLAG_N |
		((port_u8)((value & 0x0f) < 4) * PORT_FLAG_H) |
		((port_u8)(value < 0x44) * PORT_FLAG_C) |
		((port_u8)(value == 0x44) * PORT_FLAG_Z));
}
