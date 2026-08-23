#include "port_state.h"

void port_wait_for_sound_to_finish(struct wait_for_sound_state *state);

__attribute__((noinline, used)) void
port_play_default_music_fade_out_current_begin(
	struct default_music_fade_state *state)
{
	state->registers.c = 10;
	state->registers.d = 0;
	state->registers.a = state->status_flags4;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_H;
	if ((state->registers.a & 0x20) == 0) {
		state->registers.f |= PORT_FLAG_Z;
		state->dispatched = 1;
		return;
	}
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->last_music_sound_id = 0;
	state->registers.c = 8;
	state->registers.d = state->registers.c;
	state->dispatched = 1;
}

/* Port of PlayDefaultMusicFadeOutCurrent in home/audio.asm. */
__attribute__((noinline, used)) void
port_play_default_music_fade_out_current(
	struct default_music_fade_state *state,
	const struct cpu_register_state *callback_registers,
	const port_u8 callback_globals[2])
{
	port_play_default_music_fade_out_current_begin(state);
	/* Fallthrough into PlayDefaultMusicCommon is a continuation boundary. */
	state->registers = *callback_registers;
	state->status_flags4 = callback_globals[0];
	state->last_music_sound_id = callback_globals[1];
}

/* Port of PlayDefaultMusic in home/audio.asm.
 *
 * PlayDefaultMusic waits for sound to finish, then sets up for common code
 * with c=0, d=0, and last_music_sound_id=0. */
__attribute__((noinline, used)) void
port_play_default_music_begin(
	struct default_music_fade_state *state)
{
	struct wait_for_sound_state wait;
	port_u8 index;

	wait.registers = state->registers;
	wait.low_health_alarm = state->low_health_alarm;
	for (index = 0; index < 3; index++)
		wait.channel_sound_ids[index] = state->channel_sound_ids[index];
	port_wait_for_sound_to_finish(&wait);
	state->registers = wait.registers;
	for (index = 0; index < 3; index++)
		state->channel_sound_ids[index] = wait.channel_sound_ids[index];

	/* xor a; ld c, a; ld d, a */
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->registers.c = 0;
	state->registers.d = 0;

	/* ld [wLastMusicSoundID], a */
	state->last_music_sound_id = 0;

	/* Fallthrough into PlayDefaultMusicCommon is a continuation boundary. */
	state->dispatched = 1;
}

/* Port of PlayDefaultMusic in home/audio.asm. */
__attribute__((noinline, used)) void
port_play_default_music(
	struct default_music_fade_state *state,
	const struct cpu_register_state *callback_registers,
	const port_u8 callback_globals[2])
{
	port_play_default_music_begin(state);
	/* Fallthrough into PlayDefaultMusicCommon is a continuation boundary. */
	state->registers = *callback_registers;
	state->status_flags4 = callback_globals[0];
	state->last_music_sound_id = callback_globals[1];
}
