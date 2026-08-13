#include "port_state.h"

static void
tile_ids_dec(struct cpu_register_state *registers, port_u8 *value)
{
	port_u8 old = *value;

	(*value)--;
	registers->f &= PORT_FLAG_C;
	registers->f |= PORT_FLAG_N;
	if (*value == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

__attribute__((noinline, used)) void
port_copy_tile_ids_begin(struct copy_tile_ids_state *state)
{
	state->saved_h = state->registers.h;
	state->saved_l = state->registers.l;
	state->original_h = state->registers.h;
	state->original_l = state->registers.l;
	state->saved_b = state->registers.b;
	state->saved_c = state->registers.c;
	state->registers.a = state->base_tile;
	state->registers.b = state->registers.a;
}

__attribute__((noinline, used)) port_u8
port_copy_tile_ids_byte(struct copy_tile_ids_state *state)
{
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	port_u16 source = de;
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 left;
	port_u16 result;

	state->registers.a = state->fetched;
	left = state->registers.a;
	result = (port_u16)left + state->registers.b;
	state->registers.a = (port_u8)result;
	state->registers.f = 0;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (state->registers.b & 0x0f) > 0x0f)
		state->registers.f |= PORT_FLAG_H;
	if (result > 0xff)
		state->registers.f |= PORT_FLAG_C;
	de++;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	state->written = state->registers.a;
	if (source == hl)
		state->fetched = state->written;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	tile_ids_dec(&state->registers, &state->registers.c);
	return state->registers.c == 0;
}

__attribute__((noinline, used)) port_u8
port_copy_tile_ids_row(struct copy_tile_ids_state *state)
{
	port_u16 hl;
	port_u16 result;

	state->registers.h = state->saved_h;
	state->registers.l = state->saved_l;
	state->registers.b = 0;
	state->registers.c = 20;
	hl = (port_u16)(((port_u16)state->registers.h << 8) | state->registers.l);
	result = (port_u16)(hl + 20);
	state->registers.f &= PORT_FLAG_Z;
	if ((hl & 0x0fff) + 20 > 0x0fff)
		state->registers.f |= PORT_FLAG_H;
	if ((unsigned long)hl + 20 > 0xffff)
		state->registers.f |= PORT_FLAG_C;
	state->registers.h = (port_u8)(result >> 8);
	state->registers.l = (port_u8)result;
	state->saved_h = state->registers.h;
	state->saved_l = state->registers.l;
	state->registers.b = state->saved_b;
	state->registers.c = state->saved_c;
	tile_ids_dec(&state->registers, &state->registers.b);
	if (state->registers.b == 0)
		return 1;
	state->saved_b = state->registers.b;
	state->saved_c = state->registers.c;
	state->registers.a = state->base_tile;
	state->registers.b = state->registers.a;
	return 0;
}

__attribute__((noinline, used)) void
port_copy_tile_ids_finish(struct copy_tile_ids_state *state)
{
	state->registers.a = 1;
	state->auto_transfer = state->registers.a;
	state->registers.h = state->original_h;
	state->registers.l = state->original_l;
}

/* Port of CopyTileIDs in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_copy_tile_ids(struct copy_tile_ids_state *state, port_u8 memory[65536])
{
	port_u16 de;
	port_u16 hl;

	port_copy_tile_ids_begin(state);
	for (;;) {
		de = (port_u16)(((port_u16)state->registers.d << 8) |
			state->registers.e);
		hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		state->fetched = memory[de];
		port_copy_tile_ids_byte(state);
		memory[hl] = state->written;
		if (state->registers.c != 0)
			continue;
		if (port_copy_tile_ids_row(state))
			break;
	}
	port_copy_tile_ids_finish(state);
}

__attribute__((noinline, used)) void
port_copy_pic_tiles_begin(struct copy_tile_ids_state *state)
{
	state->registers.a = state->whose_turn;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.a = 0x31;
	if (state->whose_turn != 0) {
		state->registers.a = 0;
		state->registers.f = PORT_FLAG_Z;
	}
	state->base_tile = state->registers.a;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->auto_transfer = state->registers.a;
}

/* Port of CopyPicTiles in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_copy_pic_tiles(struct copy_tile_ids_state *state, port_u8 memory[65536])
{
	port_copy_pic_tiles_begin(state);
	port_copy_tile_ids(state, memory);
}

__attribute__((noinline, used)) void
port_copy_tile_ids_no_bg_transfer_begin(struct copy_tile_ids_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->auto_transfer = state->registers.a;
}

/* Port of CopyTileIDs_NoBGTransfer in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_copy_tile_ids_no_bg_transfer(struct copy_tile_ids_state *state,
	port_u8 memory[65536])
{
	port_copy_tile_ids_no_bg_transfer_begin(state);
	port_copy_tile_ids(state, memory);
}

__attribute__((noinline, used)) void
port_copy_downscaled_mon_tiles_begin(struct copy_tile_ids_state *state)
{
	state->registers.a = state->predef_h;
	state->registers.h = state->registers.a;
	state->registers.a = state->predef_l;
	state->registers.l = state->registers.a;
	state->registers.a = state->predef_d;
	state->registers.d = state->registers.a;
	state->registers.a = state->predef_e;
	state->registers.e = state->registers.a;
	state->registers.a = state->predef_b;
	state->registers.b = state->registers.a;
	state->registers.a = state->predef_c;
	state->registers.c = state->registers.a;
	state->registers.a = state->downscaled_size;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.d = 0x5b;
	state->registers.e = state->registers.a == 0 ? 0x02 : 0x1b;
	port_copy_tile_ids_no_bg_transfer_begin(state);
}

/* Port of CopyDownscaledMonTiles in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_copy_downscaled_mon_tiles(struct copy_tile_ids_state *state,
	port_u8 memory[65536])
{
	port_copy_downscaled_mon_tiles_begin(state);
	port_copy_tile_ids(state, memory);
}
