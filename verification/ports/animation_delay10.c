#include "port_state.h"

/* Port of AnimationDelay10 in engine/battle/animations.asm:
 *
 *   ld c, 10
 *   jp DelayFrames
 */

void port_delay_frames(struct delay_frame_state *, const port_u8 *);

#define DELAY_COUNT 0x0au
__attribute__((noinline, used)) void
port_animation_delay10(struct cpu_register_state *state, port_u8 *memory)
{
	static const port_u8 acknowledged_vblank[] = { 0 };
	struct delay_frame_state delay;

	state->c = DELAY_COUNT;
	delay.registers = *state;
	delay.vblank_occurred = memory[0xffd6]; /* hVBlankOccurred input */
	delay.observed_vblank = 0;
	port_delay_frames(&delay, acknowledged_vblank);
	*state = delay.registers;
	memory[0xffd6] = delay.vblank_occurred;
}
