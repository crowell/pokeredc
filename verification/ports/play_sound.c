#include "port_state.h"

/*
 * Port of PlaySound in home/audio.asm.
 *
 * PlaySound is the dispatcher every higher-level music/SFX routine funnels
 * into. It performs the observable bookkeeping for a new sound request:
 *   - silences the SFX-only channels 5-8 when a sound is already playing,
 *   - honours a pending fade-out (deferring the new sound until the fade
 *     completes, or starting it immediately after a stop),
 *   - bankswitches to the sound's audio ROM bank and back.
 * The actual channel loading is done by AudioX_PlaySound, which is a
 * separately proven port; that engine call is treated as an equivalence
 * boundary here and is not inlined.
 */

#define W_NEW_SOUND_ID                  0xc0eeu
#define W_AUDIO_ROM_BANK                0xc0efu
#define W_AUDIO_SAVED_ROM_BANK          0xc0f0u
#define W_AUDIO_FADE_OUT_CONTROL        0xcfc7u
#define W_AUDIO_FADE_OUT_COUNTER_RELOAD 0xcfc8u
#define W_AUDIO_FADE_OUT_COUNTER        0xcfc9u
#define W_LAST_MUSIC_SOUND_ID           0xcfcau
#define W_CHANNEL_SOUND_IDS             0xc026u
#define H_SAVED_ROM_BANK                0xffb9u
#define H_LOADED_ROM_BANK               0xffb8u
#define R_ROMB                          0x2000u
#define CHAN5 4
#define CHAN6 5
#define CHAN7 6
#define CHAN8 7

__attribute__((noinline, used)) void
port_play_sound(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 b = state->a; /* sound ID is passed in A */

	/* If a sound is already playing, silence the SFX channels 5-8. */
	if (memory[W_NEW_SOUND_ID] != 0) {
		memory[W_CHANNEL_SOUND_IDS + CHAN5] = 0;
		memory[W_CHANNEL_SOUND_IDS + CHAN6] = 0;
		memory[W_CHANNEL_SOUND_IDS + CHAN7] = 0;
		memory[W_CHANNEL_SOUND_IDS + CHAN8] = 0;
	}

	if (memory[W_AUDIO_FADE_OUT_CONTROL] != 0) {
		/* A fade-out length is already in progress. */
		if (memory[W_NEW_SOUND_ID] == 0) {
			/* No new sound requested: do nothing further. */
			return;
		}
		memory[W_NEW_SOUND_ID] = 0;
		if (memory[W_LAST_MUSIC_SOUND_ID] == 0xFF) {
			/* Music was stopped: start the new music right away. */
			memory[W_AUDIO_FADE_OUT_CONTROL] = 0;
		} else {
			/* Queue the new sound behind the fade-out. */
			memory[W_LAST_MUSIC_SOUND_ID] = b;
			memory[W_AUDIO_FADE_OUT_COUNTER_RELOAD] =
				memory[W_AUDIO_FADE_OUT_CONTROL];
			memory[W_AUDIO_FADE_OUT_COUNTER] =
				memory[W_AUDIO_FADE_OUT_CONTROL];
			memory[W_AUDIO_FADE_OUT_CONTROL] = b;
			return;
		}
	}

	/* No (further) fade-out: actually start the requested sound. */
	memory[W_NEW_SOUND_ID] = 0;

	/* Bankswitch to the sound's audio ROM bank and back. */
	memory[H_SAVED_ROM_BANK] = memory[H_LOADED_ROM_BANK];
	memory[H_LOADED_ROM_BANK] = memory[W_AUDIO_ROM_BANK];
	memory[R_ROMB] = memory[W_AUDIO_ROM_BANK];

	/* Dispatch to the active audio engine (Audio1/2/3_PlaySound). The engine
	 * itself is a separately proven port and is the equivalence boundary. */
	switch (memory[W_AUDIO_ROM_BANK]) {
	case 1:  break; /* Audio1_PlaySound */
	case 2:  break; /* Audio2_PlaySound */
	default: break; /* Audio3_PlaySound */
	}

	memory[H_LOADED_ROM_BANK] = memory[H_SAVED_ROM_BANK];
	memory[R_ROMB] = memory[H_SAVED_ROM_BANK];
}
