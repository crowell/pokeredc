#include "port_state.h"

struct load_trainer_pic_state {
	struct cpu_register_state registers;
	port_u8 trainer_pointer_low;
	port_u8 trainer_pointer_high;
	port_u8 link_state;
};

/* Port of _LoadTrainerPic through bank selection before decompression. */
__attribute__((noinline, used)) void
port_load_trainer_pic(struct load_trainer_pic_state *state)
{
	state->registers.e = state->trainer_pointer_low;
	state->registers.d = state->trainer_pointer_high;
	state->registers.a = state->link_state == 0 ? 0x13 : 0x04;
	state->registers.f = (port_u8)(PORT_FLAG_H |
		((port_u8)(state->link_state == 0) * PORT_FLAG_Z));
}
