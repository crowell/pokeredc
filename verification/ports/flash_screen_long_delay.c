#include "port_state.h"

void port_delay_frames(struct delay_frame_state *state,
	const port_u8 *observations);

/* Port of FlashScreenLongDelay in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_flash_screen_long_delay(struct flash_screen_long_delay_state *state)
{
	static const port_u8 acknowledged_vblank[] = { 0 };
	struct delay_frame_state delay;

	state->registers.a = state->counter;
	if (state->registers.a == 4)
		state->registers.c = 4;
	else if (state->registers.a == 3)
		state->registers.c = 2;
	else
		state->registers.c = 1;
	state->frames_waited = state->registers.c;

	delay.registers = state->registers;
	delay.vblank_occurred = 0;
	delay.observed_vblank = 0;
	port_delay_frames(&delay, acknowledged_vblank);
	state->registers = delay.registers;
}
