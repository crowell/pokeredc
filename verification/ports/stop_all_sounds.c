#include "port_state.h"

/* Port of StopAllSounds in home/init.asm.
 *
 * Stops all audio by setting up the audio engine bank, clearing audio state,
 * and playing SFX_STOP_ALL_MUSIC (0xFF).
 *
 * Modifies: A, F. */

#define W_AUDIO_ROM_BANK 0xc0efu
#define W_AUDIO_SAVED_ROM_BANK 0xc0f0u
#define W_AUDIO_FADE_OUT_CONTROL 0xcfc7u
#define W_NEW_SOUND_ID 0xc0eeu
#define W_LAST_MUSIC_SOUND_ID 0xcfca

__attribute__((noinline, used)) void
port_stop_all_sounds(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;
	(void)memory;

	/* ld a, BANK("Audio Engine 1") = 2 */
	state->a = 2;

	/* ld [wAudioROMBank], a */
	memory[W_AUDIO_ROM_BANK] = state->a;

	/* ld [wAudioSavedROMBank], a */
	memory[W_AUDIO_SAVED_ROM_BANK] = state->a;

	/* xor a */
	state->a = 0;

	/* ld [wAudioFadeOutControl], a */
	memory[W_AUDIO_FADE_OUT_CONTROL] = state->a;

	/* ld [wNewSoundID], a */
	memory[W_NEW_SOUND_ID] = state->a;

	/* ld [wLastMusicSoundID], a */
	memory[W_LAST_MUSIC_SOUND_ID] = state->a;

	/* dec a -> A = 0xFF */
	state->a = 0xFFu;

	/* jp PlaySound: the callee is an explicit no-op boundary here. */
	state->f = PORT_FLAG_N | PORT_FLAG_H | (state->f & PORT_FLAG_C);
}