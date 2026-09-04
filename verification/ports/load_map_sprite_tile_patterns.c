#include "port_state.h"

/* Port of LoadMapSpriteTilePatterns in engine/overworld/map_sprites.asm.
 *
 * The map sprite table is part of the active ROM window in the portable
 * runtime, just as it is for the other map loaders.  The two transfer
 * routines are called through their real C ports; in particular, the
 * reload-after-dialogue path uses CopyVideoData while the initial load uses
 * FarCopyData2.
 */

#define W_NUM_SPRITES 0xd4e1u
#define W_SPRITE_STATE_DATA2 0xc200u
#define W_SPRITE_PLAYER_STATE_DATA2_PICTURE_ID 0xc20du
#define W_SPRITE_PLAYER_STATE_DATA2_IMAGE_BASE_OFFSET 0xc20eu
#define H_VRAM_SLOT 0xff8du
#define H_FOUR_TILE_SPRITE_COUNT 0xff8eu
#define W_FONT_LOADED 0xcfc4u
#define H_LOADED_ROM_BANK 0xffb8u
#define R_ROMB 0x2000u
#define SPRITE_SHEET_POINTER_TABLE 0x7b27u
#define V_SPRITES 0x8000u
#define V_NPC_SPRITES 0x8800u
#define SPRITE_STATE_LENGTH 0x10u
#define NUM_SPRITE_STATE_STRUCTS 16u
#define FIRST_STILL_SPRITE 0x3du
#define BIT_FONT_LOADED 0u
#define FONT_LOADED_MASK (1u << BIT_FONT_LOADED)
#define SPRITE_SLOT_BYTES 0xc0u /* 12 tiles */

void port_read_sprite_sheet_data(struct sprite_sheet_data_state *state);
void port_far_copy_data2(struct far_copy_data2_state *state, port_u8 *memory);
void port_copy_video_data(struct cpu_register_state *state, port_u8 *memory);

static port_u16
pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
set_pair(port_u8 *high, port_u8 *low, port_u16 value)
{
	*high = (port_u8)(value >> 8);
	*low = (port_u8)value;
}

static void
load_sheet(struct cpu_register_state *r, port_u8 *memory, port_u16 table,
	struct sprite_sheet_data_state *sheet)
{
	sheet->registers = *r;
	sheet->fetched[0] = memory[table];
	sheet->fetched[1] = memory[(port_u16)(table + 1u)];
	sheet->fetched[2] = memory[(port_u16)(table + 2u)];
	sheet->fetched[3] = memory[(port_u16)(table + 3u)];
	port_read_sprite_sheet_data(sheet);
	*r = sheet->registers;
}

static void
far_copy(struct cpu_register_state *r, port_u8 *memory)
{
	struct far_copy_data2_state copy;

	copy.registers = *r;
	copy.requested_bank = r->a;
	copy.loaded_bank = memory[H_LOADED_ROM_BANK];
	copy.rom_bank = memory[R_ROMB];
	port_far_copy_data2(&copy, memory);
	*r = copy.registers;
	memory[H_LOADED_ROM_BANK] = copy.loaded_bank;
	memory[R_ROMB] = copy.rom_bank;
}

static void
copy_video(struct cpu_register_state *r, port_u8 *memory)
{
	port_copy_video_data(r, memory);
}

/* The assembly entry is a local label, but is a real callable dependency of
 * InitMapSprites and is present in pokered.sym. */
__attribute__((noinline, used)) void
port_load_map_sprite_tile_patterns(struct cpu_register_state *r, port_u8 *memory)
{
	port_u8 count = memory[W_NUM_SPRITES];
	port_u16 hl;

	r->a = count;
	if (count == 0) {
		r->f = PORT_FLAG_H | PORT_FLAG_Z;
		return;
	}
	r->f = 0;
	r->c = count;
	r->b = NUM_SPRITE_STATE_STRUCTS;
	hl = W_SPRITE_PLAYER_STATE_DATA2_PICTURE_ID;
	r->a = 0;
	r->f = PORT_FLAG_Z;
	memory[H_FOUR_TILE_SPRITE_COUNT] = 0;

	/* Copy every slot's picture ID into its temporary image-base field. */
	for (unsigned i = 0; i < NUM_SPRITE_STATE_STRUCTS; ++i) {
		port_u16 picture = (port_u16)(W_SPRITE_PLAYER_STATE_DATA2_PICTURE_ID +
			i * SPRITE_STATE_LENGTH);
		memory[(port_u16)(picture + 1u)] = memory[picture];
	}
	hl = W_SPRITE_PLAYER_STATE_DATA2_IMAGE_BASE_OFFSET + SPRITE_STATE_LENGTH;
	r->b = 0;
	r->f = PORT_FLAG_Z;

	for (unsigned slot_index = 1; slot_index <= 15 && r->c != 0;
		slot_index++, r->c--) {
		port_u16 current = (port_u16)(W_SPRITE_PLAYER_STATE_DATA2_IMAGE_BASE_OFFSET +
			slot_index * SPRITE_STATE_LENGTH);
		port_u8 picture_id = memory[current];
		port_u8 image_slot;
		port_u8 max_slot = 1;
		port_u16 table;
		struct sprite_sheet_data_state sheet;

		/* Search all preceding slots for a picture whose transfer is already
		 * resident. */
		for (unsigned previous = 0; previous < slot_index; ++previous) {
			port_u16 previous_picture =
				(port_u16)(W_SPRITE_PLAYER_STATE_DATA2_PICTURE_ID +
				previous * SPRITE_STATE_LENGTH);
			if (memory[previous_picture] == picture_id) {
				image_slot = memory[(port_u16)(previous_picture + 1u)];
				memory[current] = image_slot;
				goto next_sprite;
			}
		}

		for (unsigned previous = 0; previous < slot_index; ++previous) {
			port_u16 previous_image =
				(port_u16)(W_SPRITE_PLAYER_STATE_DATA2_IMAGE_BASE_OFFSET +
				previous * SPRITE_STATE_LENGTH);
			port_u8 candidate = memory[previous_image];
			if (candidate < 11 && candidate >= max_slot)
				max_slot = candidate;
		}
		image_slot = max_slot + 1;
		if (picture_id >= FIRST_STILL_SPRITE) {
			image_slot = (port_u8)(memory[H_FOUR_TILE_SPRITE_COUNT] + 11u);
		}
		memory[current] = image_slot;
		memory[H_VRAM_SLOT] = image_slot;

		/* SpriteSheetPointerTable entries are four bytes and picture IDs are
		 * one-based. */
		table = (port_u16)(SPRITE_SHEET_POINTER_TABLE +
			(port_u16)(picture_id - 1u) * 4u);
		set_pair(&r->h, &r->l, table);
		load_sheet(r, memory, table, &sheet);

		/* The first still frame goes to the regular NPC slots.  The two
		 * four-tile still sprites occupy the final two 4-tile locations. */
		{
			port_u16 destination;
			if (image_slot >= 11) {
				if (memory[H_FOUR_TILE_SPRITE_COUNT] == 0) {
					destination = (port_u16)(V_SPRITES + 0x780u);
					memory[H_FOUR_TILE_SPRITE_COUNT] = 1;
				} else {
					destination = (port_u16)(V_SPRITES + 0x7c0u);
				}
			} else {
				destination = (port_u16)(V_NPC_SPRITES +
					(port_u16)(image_slot - 1u) * SPRITE_SLOT_BYTES);
			}
			if ((memory[W_FONT_LOADED] & FONT_LOADED_MASK) == 0) {
				r->a = sheet.registers.a;
				r->b = 0;
				set_pair(&r->h, &r->l, destination);
				far_copy(r, memory);
			}

			if (image_slot < 11) {
				port_u16 walking_table = (port_u16)(table + 4u);
				load_sheet(r, memory, walking_table, &sheet);
				/* The walking frame follows the standing frame in the sheet. */
				set_pair(&r->d, &r->e,
					(port_u16)(pair(sheet.registers.d, sheet.registers.e) + 0xc0u));
				set_pair(&r->h, &r->l,
					(port_u16)(destination + 0x800u));
				if ((memory[W_FONT_LOADED] & FONT_LOADED_MASK) == 0) {
					r->a = sheet.registers.a;
					far_copy(r, memory);
				} else {
					r->b = sheet.registers.a;
					r->c = (port_u8)((r->c << 4) | (r->c >> 4));
					copy_video(r, memory);
				}
			}
		}

	next_sprite:
		hl = (port_u16)(current + SPRITE_STATE_LENGTH);
		set_pair(&r->h, &r->l, hl);
	}

	/* Temporary picture IDs are consumed by this routine. */
	hl = W_SPRITE_PLAYER_STATE_DATA2_PICTURE_ID;
	for (unsigned i = 0; i < NUM_SPRITE_STATE_STRUCTS; ++i)
		memory[(port_u16)(hl + i * SPRITE_STATE_LENGTH)] = 0;
	r->a = (port_u8)(W_SPRITE_PLAYER_STATE_DATA2_PICTURE_ID +
		NUM_SPRITE_STATE_STRUCTS * SPRITE_STATE_LENGTH);
	r->b = 0;
	r->f = PORT_FLAG_N | PORT_FLAG_Z;
	set_pair(&r->h, &r->l,
		W_SPRITE_PLAYER_STATE_DATA2_PICTURE_ID);
}
