#include "port_state.h"

/* Port of DelayFrames in home/delay.asm.
 *
 * Waits C frames by calling DelayFrame repeatedly.
 * Input: C = number of frames to wait.
 * Modifies: A, F, C. */

#define DELAYFRAME_ADDR 0x20AFu

/* Forward declaration of the DelayFrame port. */
__attribute__((noinline, used)) void
port_delay_frame(struct cpu_register_state *state, port_u8 *memory);

__attribute__((noinline, used)) void
port_delay_frames(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;
	(void)memory;

	/* Loop: call DelayFrame until C becomes 0 (do-while matching asm) */
	do {
		port_delay_frame(state, memory);
		state->c = (port_u8)(state->c - 1);
	} while (state->c != 0);
}