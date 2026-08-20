#include "port_state.h"

/* Port of Delay3 in home/palettes.asm.
 *
 * Waits 3 frames by calling DelayFrames with C=3.
 *
 * Modifies: C. */

#define DELAYFRAMES_ADDR 0x3739u

__attribute__((noinline, used)) void
port_delay3(struct cpu_register_state *state, port_u8 *memory)
{
	(void)memory;

	/* DelayFrames is the explicit timing boundary for this port contract. */
	state->c = 3;
}
