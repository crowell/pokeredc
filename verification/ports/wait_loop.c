#include "port_state.h"

__attribute__((noinline, used)) void
port_wait_7000_begin(struct cpu_register_state *state)
{
	state->d = 0x1b;
	state->e = 0x58;
}

__attribute__((noinline, used)) port_u8
port_wait_7000_step(struct cpu_register_state *state)
{
	port_u8 old_e = state->e;

	state->e--;
	state->d = (port_u8)(state->d - (old_e == 0));
	state->a = (port_u8)(state->d | state->e);
	state->f = state->a == 0 ? PORT_FLAG_Z : 0;
	return state->a == 0;
}

/* Port of Wait7000 in engine/gfx/palettes.asm. */
__attribute__((noinline, used)) void
port_wait_7000(struct cpu_register_state *state)
{
	port_wait_7000_begin(state);
	while (!port_wait_7000_step(state))
		;
}

/* Port of WaitLoop_15Iterations in home/serial.asm. */
__attribute__((noinline, used)) void
port_wait_loop_15_iterations(struct cpu_register_state *state)
{
	/* The final DEC is 1 -> 0: Z and N set, H clear, carry preserved. */
	state->a = 0;
	state->f = PORT_FLAG_Z | PORT_FLAG_N | (state->f & PORT_FLAG_C);
}
