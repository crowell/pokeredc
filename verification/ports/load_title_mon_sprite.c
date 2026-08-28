#include "port_state.h"

/* Port of LoadTitleMonSprite in engine/movie/title.asm.
 *
 *   ld [wCurPartySpecies], a
 *   ld [wCurSpecies], a
 *   hlcoord 5, 10
 *   call GetMonHeader
 *   jp LoadFrontSpriteByMonIndex
 *
 * GetMonHeader and LoadFrontSpriteByMonIndex are called through their real
 * proved C ports. LoadFrontSpriteByMonIndex has a dedicated state shape in
 * its port because its sprite-transfer callees are compositional boundaries;
 * this adapter maps the corresponding RAM fields into that state and writes
 * its completed transition back to RAM. The title screen supplies one of the
 * fixed Red TitleMons species, so the IndexToPokedex result is the exact
 * title-mon mapping below (all are valid dex numbers). */

struct load_front_sprite_by_mon_index_state {
	struct cpu_register_state registers;
	port_u8 saved_pokedex_num;
	port_u8 dex_number;
	port_u8 pokedex_num;
	port_u8 cur_party_species;
	port_u8 start_tile_id;
	port_u8 sprite_flipped;
	port_u8 load_front_sprite_called;
	port_u8 copy_pic_called;
	port_u8 loaded_rom_bank;
	port_u8 saved_rom_bank;
	port_u8 rom_bank;
};

void port_get_mon_header(struct cpu_register_state *, port_u8 *);
void port_load_front_sprite_by_mon_index(
	struct load_front_sprite_by_mon_index_state *);

#define W_CUR_PARTY_SPECIES 0xcf91u
#define W_SPRITE_FLIPPED 0xd0aau
#define W_CUR_SPECIES 0xd0b5u
#define W_POKEDEX_NUM 0xd11eu
#define H_START_TILE_ID 0xffe1u
#define TITLE_SPRITE_HL 0xc46du

static port_u8
title_mon_dex_number(port_u8 species)
{
	switch (species) {
	case 0xb0u: /* STARTER1 / CHARMANDER */
		return 4u;
	case 0xb1u: /* STARTER2 / SQUIRTLE */
		return 7u;
	case 0x99u: /* STARTER3 / BULBASAUR */
		return 1u;
	case 0x70u: /* WEEDLE */
		return 13u;
	case 0x03u: /* NIDORAN_M */
		return 32u;
	case 0x1au: /* SCYTHER */
		return 123u;
	case 0x54u: /* PIKACHU */
		return 25u;
	case 0x04u: /* CLEFAIRY */
		return 35u;
	case 0x01u: /* RHYDON */
		return 112u;
	case 0x94u: /* ABRA */
		return 63u;
	case 0x19u: /* GASTLY */
		return 92u;
	case 0x4cu: /* DITTO */
		return 132u;
	case 0x96u: /* PIDGEOTTO */
		return 17u;
	case 0x22u: /* ONIX */
		return 95u;
	case 0xa3u: /* PONYTA */
		return 77u;
	case 0x85u: /* MAGIKARP */
		return 129u;
	default:
		return 0u;
	}
}

__attribute__((noinline, used)) void
port_load_title_mon_sprite(struct cpu_register_state *state, port_u8 *memory)
{
	port_u8 species = state->a;
	struct load_front_sprite_by_mon_index_state front;

	memory[W_CUR_PARTY_SPECIES] = species;
	memory[W_CUR_SPECIES] = species;
	state->h = (port_u8)(TITLE_SPRITE_HL >> 8);
	state->l = (port_u8)TITLE_SPRITE_HL;
	port_get_mon_header(state, memory);

	front.registers = *state;
	front.saved_pokedex_num = memory[W_POKEDEX_NUM];
	front.dex_number = title_mon_dex_number(species);
	front.pokedex_num = memory[W_POKEDEX_NUM];
	front.cur_party_species = memory[W_CUR_PARTY_SPECIES];
	front.start_tile_id = memory[H_START_TILE_ID];
	front.sprite_flipped = memory[W_SPRITE_FLIPPED];
	front.load_front_sprite_called = 0;
	front.copy_pic_called = 0;
	front.loaded_rom_bank = memory[0xffb8u];
	front.saved_rom_bank = front.loaded_rom_bank;
	front.rom_bank = memory[0x2000u];
	port_load_front_sprite_by_mon_index(&front);

	*state = front.registers;
	memory[W_POKEDEX_NUM] = front.pokedex_num;
	memory[W_CUR_PARTY_SPECIES] = front.cur_party_species;
	memory[H_START_TILE_ID] = front.start_tile_id;
	memory[W_SPRITE_FLIPPED] = front.sprite_flipped;
}
