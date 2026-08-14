#include "port_state.h"

/* Port of Delay3 in home/palettes.asm.
 *
 * Waits 3 frames by calling DelayFrames with C=3.
 *
 * Modifies: C. */

#define DELAYFRAMES_ADDR 0x3739u

/* Forward declaration of the DelayFrame port. */
__attribute__((noinline, used)) void
port_delay_frame(struct cpu_register_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_delay3(struct cpu_register_state *state, port_u8 *memory)
{
	(void)memory;

	/* ld c, 3 */
	state->c = 3;

	/* jp DelayFrames */
	port_delay_frame(state, memory);
}