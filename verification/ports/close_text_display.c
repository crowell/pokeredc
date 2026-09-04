#include "port_state.h"

#define W_CUR_MAP 0xd35eu
#define W_MAP_PAL_OFFSET 0xd35du
#define W_CURRENT_TILE_BLOCK_MAP_VIEW_POINTER 0xd35fu
#define W_Y_BLOCK_COORD 0xd363u
#define W_X_BLOCK_COORD 0xd364u
#define W_FONT_LOADED 0xcfc4u
#define W_STATUS_FLAGS6 0xd732u
#define W_MAP_VIEW_VRAM_POINTER 0xd526u
#define W_TILESET_BANK 0xd52bu
#define W_TILESET_BLOCKS_PTR 0xd52cu
#define H_ROM_BANK_TEMP 0xff8bu
#define H_SAVED_ROM_BANK 0xffb9u
#define H_LOADED_ROM_BANK 0xffb8u
#define H_AUTO_BG_TRANSFER_ENABLED 0xffbau
#define H_MAP_WIDTH 0xff8cu
#define H_WY 0xffb0u
#define R_BGP 0xff47u
#define R_OBP0 0xff48u
#define R_OBP1 0xff49u
#define R_ROMB 0x2000u
#define BIT_FONT_LOADED 0u
#define BIT_FLY_WARP 3u
#define SPRITE_ORIG_FACING 0xc219u
#define SPRITE_FACING 0xc119u
#define SPRITE_STATE_STRIDE 16u
#define RESTORE_FACING_COUNT 15u
#define INIT_MAP_SPRITES_BANK 5u

void port_switch_to_map_rom_bank(struct switch_to_map_rom_bank_state *);
void port_delay_frame(struct delay_frame_state *, const port_u8 *);
void port_load_gb_pal(struct load_gb_pal_state *);
void port_init_map_sprites(struct cpu_register_state *, port_u8 *);
void port_load_player_sprite_graphics(struct cpu_register_state *, port_u8 *);
void port_load_current_map_view(struct load_current_map_view_state *, port_u8 *);
void port_update_sprites(struct cpu_register_state *, port_u8 *);

static void
restore_sprite_facing(port_u8 *memory, struct cpu_register_state *r)
{
	port_u16 hl = SPRITE_ORIG_FACING;
	port_u16 de = SPRITE_STATE_STRIDE;
	port_u8 count = RESTORE_FACING_COUNT;

	while (count-- != 0u) {
		port_u8 value = memory[hl];
		port_u16 sum;
		port_u8 old_count = (port_u8)(count + 1u);

		r->a = value;
		memory[(port_u16)(hl - 0x0100u)] = value;
		sum = (port_u16)(hl + de);
		r->f = (port_u8)((r->f & PORT_FLAG_Z) |
		    (((hl & 0x0fffu) + (de & 0x0fffu)) > 0x0fffu ?
		    PORT_FLAG_H : 0) | (sum < hl ? PORT_FLAG_C : 0));
		hl = sum;
		r->c = old_count;
		r->c = (port_u8)(r->c - 1u);
		r->f = (port_u8)((r->f & PORT_FLAG_C) | PORT_FLAG_N |
		    (r->c == 0u ? PORT_FLAG_Z : 0) |
		    ((old_count & 0x0fu) == 0u ? PORT_FLAG_H : 0));
	}
	r->h = (port_u8)(hl >> 8);
	r->l = (port_u8)hl;
	r->d = (port_u8)(de >> 8);
	r->e = (port_u8)de;
	r->c = 0;
}

static void
switch_map_bank(struct cpu_register_state *r, port_u8 *memory)
{
	struct switch_to_map_rom_bank_state bank = {0};

	bank.registers = *r;
	bank.registers.a = memory[W_CUR_MAP];
	bank.loaded_rom_bank = memory[H_LOADED_ROM_BANK];
	bank.mapper_bank = memory[R_ROMB];
	bank.home_temp = memory[H_ROM_BANK_TEMP];
	bank.home_saved_rom_bank = memory[H_SAVED_ROM_BANK];
	port_switch_to_map_rom_bank(&bank);
	*r = bank.registers;
	memory[H_LOADED_ROM_BANK] = bank.loaded_rom_bank;
	memory[R_ROMB] = bank.mapper_bank;
	memory[H_ROM_BANK_TEMP] = bank.home_temp;
	memory[H_SAVED_ROM_BANK] = bank.home_saved_rom_bank;
}

static void
load_current_view(struct cpu_register_state *r, port_u8 *memory)
{
	struct load_current_map_view_state view = {0};
	port_u16 map_view = (port_u16)(memory[W_CURRENT_TILE_BLOCK_MAP_VIEW_POINTER] |
	    ((port_u16)memory[W_CURRENT_TILE_BLOCK_MAP_VIEW_POINTER + 1u] << 8));
	port_u16 blocks = (port_u16)(memory[W_TILESET_BLOCKS_PTR] |
	    ((port_u16)memory[W_TILESET_BLOCKS_PTR + 1u] << 8));

	view.registers = *r;
	view.tileset_bank = memory[W_TILESET_BANK];
	view.loaded_rom_bank = memory[H_LOADED_ROM_BANK];
	view.mapper_bank = memory[R_ROMB];
	view.map_view_pointer_low = (port_u8)map_view;
	view.map_view_pointer_high = (port_u8)(map_view >> 8);
	view.map_width = memory[H_MAP_WIDTH];
	view.y_block_coord = memory[W_Y_BLOCK_COORD];
	view.x_block_coord = memory[W_X_BLOCK_COORD];
	view.tileset_blocks_low = (port_u8)blocks;
	view.tileset_blocks_high = (port_u8)(blocks >> 8);
	port_load_current_map_view(&view, memory);
	*r = view.registers;
	memory[H_LOADED_ROM_BANK] = view.loaded_rom_bank;
	memory[R_ROMB] = view.mapper_bank;
	memory[W_CURRENT_TILE_BLOCK_MAP_VIEW_POINTER] = view.map_view_pointer_low;
	memory[W_CURRENT_TILE_BLOCK_MAP_VIEW_POINTER + 1u] = view.map_view_pointer_high;
	memory[H_MAP_WIDTH] = view.map_width;
	memory[W_Y_BLOCK_COORD] = view.y_block_coord;
	memory[W_X_BLOCK_COORD] = view.x_block_coord;
	memory[W_TILESET_BANK] = view.tileset_bank;
	memory[W_TILESET_BLOCKS_PTR] = view.tileset_blocks_low;
	memory[W_TILESET_BLOCKS_PTR + 1u] = view.tileset_blocks_high;
}

/* Port of CloseTextDisplay in home/text_script.asm. */
__attribute__((noinline, used)) void
port_close_text_display(struct close_text_display_state *state,
	port_u8 *memory)
{
	struct delay_frame_state delay = {0};
	struct load_gb_pal_state palette = {0};
	port_u8 observations[] = {state->observed_vblank, 0};

	switch_map_bank(&state->registers, memory);
	memory[H_WY] = 0x90;
	delay.registers = state->registers;
	delay.observed_vblank = state->observed_vblank;
	port_delay_frame(&delay, observations);
	state->registers = delay.registers;

	palette.registers = state->registers;
	palette.map_pal_offset = state->map_pal_offset;
	palette.fetched[0] = state->palette[0];
	palette.fetched[1] = state->palette[1];
	palette.fetched[2] = state->palette[2];
	port_load_gb_pal(&palette);
	state->registers = palette.registers;
	state->palette[0] = palette.background_palette;
	state->palette[1] = palette.object_palette0;
	state->palette[2] = palette.object_palette1;
	memory[R_BGP] = palette.background_palette;
	memory[R_OBP0] = palette.object_palette0;
	memory[R_OBP1] = palette.object_palette1;
	memory[H_AUTO_BG_TRANSFER_ENABLED] = 0;

	restore_sprite_facing(memory, &state->registers);
	state->registers.a = INIT_MAP_SPRITES_BANK;
	memory[H_LOADED_ROM_BANK] = INIT_MAP_SPRITES_BANK;
	memory[R_ROMB] = INIT_MAP_SPRITES_BANK;
	port_init_map_sprites(&state->registers, memory);
	state->registers.h = (port_u8)(W_FONT_LOADED >> 8);
	state->registers.l = (port_u8)W_FONT_LOADED;
	memory[W_FONT_LOADED] &= (port_u8)~(1u << BIT_FONT_LOADED);
	state->registers.a = memory[W_STATUS_FLAGS6];
	state->registers.f = (port_u8)((state->registers.f & PORT_FLAG_C) |
	    PORT_FLAG_H | ((state->registers.a & (port_u8)(1u << BIT_FLY_WARP)) == 0u ?
	    PORT_FLAG_Z : 0));
	if ((memory[W_STATUS_FLAGS6] & (port_u8)(1u << BIT_FLY_WARP)) == 0u)
		port_load_player_sprite_graphics(&state->registers, memory);
	load_current_view(&state->registers, memory);
	state->registers.a = state->saved_a;
	state->registers.f = state->saved_f;
	memory[H_LOADED_ROM_BANK] = state->saved_a;
	memory[R_ROMB] = state->saved_a;
	port_update_sprites(&state->registers, memory);
}
