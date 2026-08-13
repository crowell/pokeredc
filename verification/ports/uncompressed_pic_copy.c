#include "port_state.h"

static void
copy_uncompressed_pic_to_hl(struct uncompressed_pic_copy_state *state)
{
	port_u16 base = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 tile = state->registers.a;
	port_u8 index = 0;
	port_u8 column;
	port_u8 row;
	port_u16 last_add_left;

	state->registers.b = 7;
	state->registers.c = 7;
	state->registers.d = 0;
	state->registers.e = 20;
	if (state->sprite_flipped == 0) {
		for (column = 0; column < 7; column++)
			for (row = 0; row < 7; row++)
				state->writes[index++] = tile++;
		state->registers.h = (port_u8)((port_u16)(base + 7) >> 8);
		state->registers.l = (port_u8)(base + 7);
		last_add_left = (port_u16)(base + 126);
	} else {
		for (column = 0; column < 7; column++)
			for (row = 0; row < 7; row++)
				state->writes[index++] = tile++;
		state->registers.h = (port_u8)((port_u16)(base - 1) >> 8);
		state->registers.l = (port_u8)(base - 1);
		last_add_left = (port_u16)(base + 120);
	}
	state->registers.a = tile;
	state->registers.b = 0;
	state->registers.c = 7;
	state->registers.f = PORT_FLAG_Z | PORT_FLAG_N;
	if (last_add_left > 0xffeb)
		state->registers.f |= PORT_FLAG_C;
}

/* Port of CopyUncompressedPicToHL in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_copy_uncompressed_pic_to_hl(struct uncompressed_pic_copy_state *state)
{
	copy_uncompressed_pic_to_hl(state);
}

/* Port of CopyUncompressedPicToTilemap in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_copy_uncompressed_pic_to_tilemap(
	struct uncompressed_pic_copy_state *state)
{
	state->registers.h = state->predef_h;
	state->registers.l = state->predef_l;
	state->registers.a = state->start_tile_id;
	copy_uncompressed_pic_to_hl(state);
}
