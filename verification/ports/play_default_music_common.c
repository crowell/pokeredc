#include "port_state.h"

__attribute__((noinline, used)) void
port_play_sound(struct cpu_register_state *state, port_u8 *memory);

/*
 * Port of PlayDefaultMusicCommon in home/audio.asm.
 *
 * Continuation of PlayDefaultMusic / PlayDefaultMusicFadeOutCurrent. Picks the
 * default map music depending on the walk/bike/surf state (or the map's music
 * for walking), reconciles the audio ROM bank with the map's music bank via
 * CompareMapMusicBankWithCurrentBank, skips playback when the default music is
 * already playing, and otherwise starts it through PlaySound. c and d are
 * caller-supplied registers (fade-out length and a "fade current music first"
 * flag); state->c and state->d carry them in.
 */

#define W_WALK_BIKE_SURF_STATE       0xd700u
#define W_MAP_MUSIC_SOUND_ID         0xd35bu
#define W_MAP_MUSIC_ROM_BANK         0xd35cu
#define W_AUDIO_ROM_BANK             0xc0efu
#define W_AUDIO_SAVED_ROM_BANK       0xc0f0u
#define W_AUDIO_FADE_OUT_CONTROL     0xcfc7u
#define W_LAST_MUSIC_SOUND_ID        0xcfcau
#define W_NEW_SOUND_ID               0xc0eeu

#define MUSIC_BIKE_RIDING     0xD2u
#define MUSIC_SURFING         0xD6u
#define BANK_MUSIC_BIKE_RIDING 0x1Fu

__attribute__((noinline, used)) void
port_play_default_music_common(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 surf_state = memory[W_WALK_BIKE_SURF_STATE];
	port_u8 c = state->c;
	port_u8 d = state->d;
	port_u8 b;
	int carry = 0;

	if (surf_state == 0) {
		/* Walking: use the map's music and reconcile the audio bank. */
		b = memory[W_MAP_MUSIC_SOUND_ID];
		{
			port_u8 map_bank = memory[W_MAP_MUSIC_ROM_BANK];
			if (memory[W_AUDIO_ROM_BANK] != map_bank) {
				/* CompareMapMusicBankWithCurrentBank: banks differ. */
				if (c == 0)
					memory[W_AUDIO_ROM_BANK] = map_bank;
				memory[W_AUDIO_SAVED_ROM_BANK] = map_bank;
				carry = 1;
			} else {
				memory[W_AUDIO_SAVED_ROM_BANK] =
					memory[W_AUDIO_ROM_BANK];
				carry = 0;
			}
		}
		/* jr c, .next4 (play); else .next3 (already-playing check). */
		if (!carry && memory[W_LAST_MUSIC_SOUND_ID] == b)
			return;
		/* else fall through to .next4 */
	} else {
		/* Biking (1) or surfing (2). */
		if (surf_state == 2)
			b = MUSIC_SURFING;
		else
			b = MUSIC_BIKE_RIDING;
		/* ld a, d; and a; ld a, BANK(Music_BikeRiding) */
		if (d == 0)
			memory[W_AUDIO_ROM_BANK] = BANK_MUSIC_BIKE_RIDING;
		memory[W_AUDIO_SAVED_ROM_BANK] = BANK_MUSIC_BIKE_RIDING;
		/* jr .next3 */
		if (memory[W_LAST_MUSIC_SOUND_ID] == b)
			return;
	}

	/* .next4: start the default music. */
	memory[W_AUDIO_FADE_OUT_CONTROL] = c;
	memory[W_LAST_MUSIC_SOUND_ID] = b;
	memory[W_NEW_SOUND_ID] = b;
	state->a = b;
	port_play_sound(state, memory);
}
