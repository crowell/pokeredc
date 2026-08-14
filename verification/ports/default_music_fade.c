#include "port_state.h"

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
	/* call WaitForSoundToFinish - modeled as no-op in port */
	(void)state; /* wait is no-op in port */

	/* xor a; ld c, a; ld d, a */
	state->registers.a = 0;
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