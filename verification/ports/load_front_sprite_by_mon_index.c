#include "port_state.h"

#define W_POKEDEX_NUM 0xd11eu
#define W_CUR_PARTY_SPECIES 0xcf91u
#define W_SPRITE_FLIPPED 0xd0aau
#define H_START_TILE_ID 0xffe1u
#define NUM_POKEMON 151u
#define RHYDON 1u

/* Port of LoadFrontSpriteByMonIndex (home/pokemon.asm).
 *
 * Converts wCurPartySpecies to a Pokedex number via predef IndexToPokedex
 * (boundary), restores wPokedexNum, then applies the Rhydon trap: an invalid
 * dex number (0 or >NUM_POKEMON) fails safe by setting wCurPartySpecies to
 * RHYDON. A valid dex number loads the front sprite (LoadMonFrontSprite and
 * CopyUncompressedPicToHL are boundaries) and sets hStartTileID = 0 and
 * wSpriteFlipped = 0. The ROM-bank switch is pushed/popped, so its net effect
 * is unchanged (boundary).
 *
 * The dex number produced by predef IndexToPokedex cannot be computed in the
 * port without the species table, so it is taken from A (state->a), the
 * register convention used to carry it in the harness model. */
__attribute__((noinline, used)) void
port_load_front_sprite_by_mon_index(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 saved_dex = memory[W_POKEDEX_NUM];
	port_u8 dex = state->a; /* A = dex number produced by predef IndexToPokedex (boundary) */
	/* pop bc; ld [hl], b : restore wPokedexNum */
	memory[W_POKEDEX_NUM] = saved_dex;

	if (dex == 0 || dex > NUM_POKEMON) {
		/* .invalidDexNumber : Rhydon trap */
		memory[W_CUR_PARTY_SPECIES] = RHYDON;
		return;
	}

	/* .validDexNumber : LoadMonFrontSprite + CopyUncompressedPicToHL boundaries */
	memory[H_START_TILE_ID] = 0;
	memory[W_SPRITE_FLIPPED] = 0;
	/* hLoadedROMBank / rROMB switched to BANK(CopyUncompressedPicToHL) then
	 * restored: net no change (boundary). */
}
