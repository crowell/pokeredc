#include "port_state.h"

struct load_player_back_pic_state {
	struct cpu_register_state registers;
	port_u8 battle_type;
};

/* Port of LoadPlayerBackPic through Red/Old Man pointer selection. */
__attribute__((noinline, used)) void
port_load_player_back_pic(struct load_player_back_pic_state *state)
{
	port_u8 old = state->battle_type;
	port_u8 result = (port_u8)(old - 1);
	state->registers.a = result;
	state->registers.f = (state->registers.f & PORT_FLAG_C) | PORT_FLAG_N |
		((port_u8)((old & 0x0f) == 0) * PORT_FLAG_H) |
		((port_u8)(result == 0) * PORT_FLAG_Z);
	if (result == 0) {
		state->registers.d = 0x7e;
		state->registers.e = 0x9a;
	} else {
		state->registers.d = 0x7e;
		state->registers.e = 0x0a;
	}
}
