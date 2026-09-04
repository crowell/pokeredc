#include "port_state.h"

#define W_TILE_MAP ((port_u16)0xc3a0u)
#define W_NAMING_SCREEN_TYPE ((port_u16)0xd07du)
#define W_CUR_PARTY_SPECIES ((port_u16)0xcf91u)
#define W_MON_PARTY_SPRITE_SPECIES ((port_u16)0xcd5du)
#define W_NAMED_OBJECT_INDEX ((port_u16)0xd11eu)
#define W_NAME_BUFFER ((port_u16)0xcd6du)
#define YOUR_TEXT_STRING ((port_u16)0x693fu)
#define RIVALS_TEXT_STRING ((port_u16)0x6945u)
#define NAME_TEXT_STRING ((port_u16)0x694du)
#define NICKNAME_TEXT_STRING ((port_u16)0x6953u)
#define NAME_MON_SCREEN ((port_u8)2u)
#define BLANK_TILE ((port_u8)0xc9u)

struct get_mon_name_state {
	struct cpu_register_state registers;
	port_u8 named_object_index;
	port_u8 loaded_bank;
	port_u8 rom_bank;
};

struct write_party_oam_species_private_state {
	struct cpu_register_state registers;
	port_u8 mon_species;
	port_u8 party_index;
	port_u8 sprite_id;
	port_u8 pokedex_num;
	port_u8 sprite_flags;
};

struct print_naming_text_state {
	struct cpu_register_state registers;
	port_u8 current_species;
	port_u8 sprite_id;
	port_u8 pokedex_num;
	port_u8 sprite_flags;
};

void port_get_mon_name(struct get_mon_name_state *, port_u8 *);
void port_place_string(struct cpu_register_state *, port_u8 *);
void port_write_mon_party_sprite_oam_by_species_private(
	struct write_party_oam_species_private_state *, port_u8 *);

static port_u16
coord(port_u8 x, port_u8 y)
{
	return (port_u16)(W_TILE_MAP + (port_u16)y * 20u + x);
}

/* Port of PrintNamingText in engine/menus/naming_screen.asm. */
__attribute__((noinline, used)) void
port_print_naming_text(struct print_naming_text_state *state, port_u8 *memory)
{
	struct cpu_register_state *registers = &state->registers;
	struct write_party_oam_species_private_state sprite;
	struct get_mon_name_state name;
	port_u8 type = memory[W_NAMING_SCREEN_TYPE];
	port_u16 destination;

	registers->h = (port_u8)(coord(0, 1) >> 8);
	registers->l = (port_u8)coord(0, 1);
	registers->d = (port_u8)(YOUR_TEXT_STRING >> 8);
	registers->e = (port_u8)YOUR_TEXT_STRING;

	if (type == 0u) {
		port_place_string(registers, memory);
		registers->d = (port_u8)(NAME_TEXT_STRING >> 8);
		registers->e = (port_u8)NAME_TEXT_STRING;
		registers->h = registers->b;
		registers->l = registers->c;
		port_place_string(registers, memory);
		return;
	}

	registers->d = (port_u8)(RIVALS_TEXT_STRING >> 8);
	registers->e = (port_u8)RIVALS_TEXT_STRING;
	if (type == 1u) {
		port_place_string(registers, memory);
		registers->d = (port_u8)(NAME_TEXT_STRING >> 8);
		registers->e = (port_u8)NAME_TEXT_STRING;
		registers->h = registers->b;
		registers->l = registers->c;
		port_place_string(registers, memory);
		return;
	}

	memory[W_MON_PARTY_SPRITE_SPECIES] = memory[W_CUR_PARTY_SPECIES];
	sprite.registers = *registers;
	sprite.mon_species = memory[W_MON_PARTY_SPRITE_SPECIES];
	sprite.party_index = 0;
	sprite.sprite_id = state->sprite_id;
	sprite.pokedex_num = state->pokedex_num;
	sprite.sprite_flags = state->sprite_flags;
	port_write_mon_party_sprite_oam_by_species_private(&sprite, memory);
	*registers = sprite.registers;

	memory[W_NAMED_OBJECT_INDEX] = registers->a;
	name.registers = *registers;
	name.named_object_index = memory[W_NAMED_OBJECT_INDEX];
	name.rom_bank = 0;
	port_get_mon_name(&name, memory);
	*registers = name.registers;
	registers->h = (port_u8)(coord(4, 1) >> 8);
	registers->l = (port_u8)coord(4, 1);
	registers->d = (port_u8)(W_NAME_BUFFER >> 8);
	registers->e = (port_u8)W_NAME_BUFFER;
	port_place_string(registers, memory);

	destination = (port_u16)(registers->b << 8 | registers->c);
	memory[(port_u16)(destination + 1u)] = BLANK_TILE;
	registers->h = (port_u8)(coord(1, 3) >> 8);
	registers->l = (port_u8)coord(1, 3);
	registers->d = (port_u8)(NICKNAME_TEXT_STRING >> 8);
	registers->e = (port_u8)NICKNAME_TEXT_STRING;
	port_place_string(registers, memory);
}
