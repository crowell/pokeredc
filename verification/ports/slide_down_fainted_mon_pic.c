#include "port_state.h"

struct slide_down_fainted_state {
	struct cpu_register_state registers;
	port_u8 status_flags5;
};

/* Port of SlideDownFaintedMonPic setup through the first slide-step loop. */
__attribute__((noinline, used)) void
port_slide_down_fainted_mon_pic(struct slide_down_fainted_state *state)
{
	state->registers.a = state->status_flags5 | 0x04;
	state->status_flags5 = state->registers.a;
	state->registers.b = 7;
}
