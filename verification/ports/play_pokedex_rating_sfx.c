#include "port_state.h"

__attribute__((noinline, used)) void
port_play_sound(struct cpu_register_state *state, port_u8 *memory);
__attribute__((noinline, used)) void
port_play_default_music_common(struct cpu_register_state *state, port_u8 *memory);

/*
 * Port of PlayPokedexRatingSfx in audio/pokedex_rating_sfx.asm.
 *
 * Maps the number of owned Pokemon (hDexRatingNumMonsOwned) to one of seven
 * rating jingles, stops the current music, plays the jingle, then falls
 * through to the default-map-music routine. The actual sound starts are
 * performed through PlayMusic -> PlaySound and PlayDefaultMusic ->
 * PlayDefaultMusicCommon, both modelled here by chaining the relevant ports.
 */

#define W_NEW_SOUND_ID               0xc0eeu
#define W_AUDIO_ROM_BANK             0xc0efu
#define W_AUDIO_SAVED_ROM_BANK       0xc0f0u
#define W_AUDIO_FADE_OUT_CONTROL     0xcfc7u
#define W_LAST_MUSIC_SOUND_ID        0xcfcau
#define H_DEX_RATING_NUM_MONS        0xffdcu

#define SFX_STOP_ALL_MUSIC 0xFFu

/* PokedexRatingSfxPointers: (sound_id, bank) per rating tier. */
static const port_u8 POKEDEX_RATING_SFX[7][2] = {
	{ 0xA5u, 0x1Fu }, /* SFX_DENIED,         BANK(SFX_Denied_3) */
	{ 0x91u, 0x02u }, /* SFX_POKEDEX_RATING, BANK(SFX_Pokedex_Rating_1) */
	{ 0x86u, 0x02u }, /* SFX_GET_ITEM_1,     BANK(SFX_Get_Item1_1) */
	{ 0x9Au, 0x08u }, /* SFX_CAUGHT_MON,     BANK(SFX_Caught_Mon) */
	{ 0x86u, 0x08u }, /* SFX_LEVEL_UP,       BANK(SFX_Level_Up) */
	{ 0x94u, 0x02u }, /* SFX_GET_KEY_ITEM,   BANK(SFX_Get_Key_Item_1) */
	{ 0x89u, 0x02u }, /* SFX_GET_ITEM_2,     BANK(SFX_Get_Item2_1) */
};

/* Owned-mon thresholds (the original asm's trailing 0xFF sentinel is the
 * loop break condition and is not needed as a table entry here). */
static const port_u8 OWNED_MON_VALUES[6] = { 10, 40, 60, 90, 120, 150 };

__attribute__((noinline, used)) void
port_play_pokedex_rating_sfx(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 a = memory[H_DEX_RATING_NUM_MONS];
	int c = 0;
	int i;

	/* Count the rating tiers whose threshold the owned-mon count meets. */
	for (i = 0; i < 6; i++) {
		if (a < OWNED_MON_VALUES[i])
			break;
		c++;
	}

	/* ld a, SFX_STOP_ALL_MUSIC; ld [wNewSoundID], a;
	 * call PlaySoundWaitForCurrent (the wait is a no-op for observable state). */
	memory[W_NEW_SOUND_ID] = SFX_STOP_ALL_MUSIC;
	state->a = SFX_STOP_ALL_MUSIC;
	port_play_sound(state, memory);

	/* Load the chosen (sound_id, bank) and play it via PlayMusic. */
	{
		port_u8 sound_id = POKEDEX_RATING_SFX[c][0];
		port_u8 bank = POKEDEX_RATING_SFX[c][1];

		memory[W_NEW_SOUND_ID] = sound_id;
		memory[W_AUDIO_FADE_OUT_CONTROL] = 0;
		memory[W_AUDIO_ROM_BANK] = bank;
		memory[W_AUDIO_SAVED_ROM_BANK] = bank;
		state->a = sound_id;
		port_play_sound(state, memory);
	}

	/* jp PlayDefaultMusic: wait, reset default-music inputs, then run the
	 * common default-music routine for the current map. */
	memory[W_LAST_MUSIC_SOUND_ID] = 0;
	state->c = 0;
	state->d = 0;
	port_play_default_music_common(state, memory);
}
