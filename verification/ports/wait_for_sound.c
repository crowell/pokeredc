#include "port_state.h"

/* Port of WaitForSoundToFinish in home/delay.asm. */
__attribute__((noinline, used)) void
port_wait_for_sound_to_finish(struct wait_for_sound_state *state)
{
	port_u8 saved_h;
	port_u8 saved_l;

	state->registers.a = state->low_health_alarm;
	state->registers.a &= 0x80;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if (state->registers.a != 0)
		return;
	saved_h = state->registers.h;
	saved_l = state->registers.l;
	/* Nonzero polls stutter until the volatile channel IDs all become zero. */
	state->channel_sound_ids[0] = 0;
	state->channel_sound_ids[1] = 0;
	state->channel_sound_ids[2] = 0;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->registers.h = saved_h;
	state->registers.l = saved_l;
}
