#include "port_state.h"

void port_gb_pal_white_out(struct black_screen_state *state);
void port_delay3(struct cpu_register_state *state, port_u8 *memory);

/*
 * Port of GBPalWhiteOutWithDelay3 in home/palettes.asm.
 *
 * The assembly calls GBPalWhiteOut and then falls through into Delay3.  Keep
 * that composition explicit: both independently ported callees are invoked,
 * and Delay3 carries the continuation to DelayFrames with C = 3.
 */
__attribute__((noinline, used)) void
port_gb_pal_white_out_with_delay3(struct black_screen_state *state)
{
	static port_u8 delay_memory[1];

	port_gb_pal_white_out(state);
	port_delay3(&state->registers, delay_memory);
}
