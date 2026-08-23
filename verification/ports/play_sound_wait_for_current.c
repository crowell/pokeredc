#include "port_state.h"

void port_wait_for_sound_to_finish(struct wait_for_sound_state *state);
void port_play_sound(struct play_sound_state *state);

/* Port of PlaySoundWaitForCurrent in home/delay.asm. */
__attribute__((noinline, used)) void
port_play_sound_wait_for_current(struct play_sound_state *state)
{
	struct wait_for_sound_state wait;
	port_u8 saved_a = state->registers.a;
	port_u8 saved_f = state->registers.f;

	wait.registers = state->registers;
	wait.low_health_alarm = state->low_health_alarm;
	wait.channel_sound_ids[0] = state->channel_sound_ids[0];
	wait.channel_sound_ids[1] = state->channel_sound_ids[1];
	wait.channel_sound_ids[2] = state->channel_sound_ids[3];
	port_wait_for_sound_to_finish(&wait);
	state->registers = wait.registers;
	state->channel_sound_ids[0] = wait.channel_sound_ids[0];
	state->channel_sound_ids[1] = wait.channel_sound_ids[1];
	state->channel_sound_ids[3] = wait.channel_sound_ids[2];

	state->registers.a = saved_a;
	state->registers.f = saved_f;
	port_play_sound(state);
}
