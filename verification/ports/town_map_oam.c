#include "port_state.h"

static void
town_map_cp(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;

	registers->f = PORT_FLAG_N;
	if (left == right)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
}

static void
town_map_add_hl(struct cpu_register_state *registers, port_u16 right)
{
	port_u16 left = (port_u16)(((port_u16)registers->h << 8) |
		registers->l);
	port_u16 result = (port_u16)(left + right);
	port_u8 saved_z = registers->f & PORT_FLAG_Z;

	registers->f = saved_z;
	if ((left & 0x0fff) + (right & 0x0fff) > 0x0fff)
		registers->f |= PORT_FLAG_H;
	if ((unsigned long)left + right > 0xffff)
		registers->f |= PORT_FLAG_C;
	registers->h = (port_u8)(result >> 8);
	registers->l = (port_u8)result;
}

/* Port of WriteAsymmetricMonPartySpriteOAM in engine/items/town_map.asm. */
__attribute__((noinline, used)) void
port_write_asymmetric_mon_party_sprite_oam(struct asymmetric_oam_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 original_b = state->registers.b;
	port_u8 original_c = state->registers.c;
	port_u8 tile = state->base_tile;
	port_u8 row;
	port_u8 column;
	port_u8 index = 0;
	port_u8 row_y = original_b;
	port_u8 column_x;
	port_u16 wide;

	for (row = 0; row != 2; row++) {
		column_x = original_c;
		for (column = 0; column != 2; column++) {
			state->output[index++] = row_y;
			state->output[index++] = column_x;
			state->output[index++] = tile++;
			state->output[index++] = 0;
			column_x = (port_u8)(column_x + 8);
		}
		row_y = (port_u8)(row_y + 8);
	}
	state->base_tile = tile;
	hl = (port_u16)(hl + 16);
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.a = row_y;
	state->registers.b = row_y;
	state->registers.c = original_c;
	state->registers.d = 0;
	state->registers.e = 2;
	wide = (port_u16)(port_u8)(original_b + 8) + 8;
	state->registers.f = PORT_FLAG_Z | PORT_FLAG_N;
	if (wide > 0xff)
		state->registers.f |= PORT_FLAG_C;
}

__attribute__((noinline, used)) void
port_write_town_map_sprite_oam_begin(struct asymmetric_oam_state *state)
{
	port_u16 bc = (port_u16)(((port_u16)state->registers.b << 8) |
		state->registers.c);
	port_u16 adjusted = (port_u16)(bc + 0xfcfc);
	port_u8 saved_z = state->registers.f & PORT_FLAG_Z;

	state->registers.f = saved_z;
	if ((0xfcfc & 0x0fff) + (bc & 0x0fff) > 0x0fff)
		state->registers.f |= PORT_FLAG_H;
	if ((unsigned long)0xfcfc + bc > 0xffff)
		state->registers.f |= PORT_FLAG_C;

	state->registers.b = (port_u8)(adjusted >> 8);
	state->registers.c = (port_u8)adjusted;
}

__attribute__((noinline, used)) void
port_write_town_map_sprite_oam(struct asymmetric_oam_state *state)
{
	port_write_town_map_sprite_oam_begin(state);
	port_write_asymmetric_mon_party_sprite_oam(state);
}

__attribute__((noinline, used)) void
port_write_player_or_bird_sprite_oam_begin(struct asymmetric_oam_state *state)
{
	state->registers.a = state->base_tile;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if (state->registers.a == 0) {
		state->registers.h = 0xc3;
		state->registers.l = 0x90;
	} else {
		state->registers.h = 0xc3;
		state->registers.l = 0x80;
	}
}

__attribute__((noinline, used)) void
port_write_player_or_bird_sprite_oam(struct asymmetric_oam_state *state)
{
	port_write_player_or_bird_sprite_oam_begin(state);
	port_write_town_map_sprite_oam(state);
}

/* Port of WriteSymmetricMonPartySpriteOAM in engine/items/town_map.asm. */
__attribute__((noinline, used)) void
port_write_symmetric_mon_party_sprite_oam(struct symmetric_oam_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 original_b = state->registers.b;
	port_u8 original_c = state->registers.c;
	port_u8 tile = state->base_tile;
	port_u8 row_y = original_b;
	port_u8 column_x;
	port_u8 row;
	port_u8 column;
	port_u8 index = 0;
	port_u16 wide;

	state->attributes = 0;
	for (row = 0; row != 2; row++) {
		column_x = original_c;
		for (column = 0; column != 2; column++) {
			state->output[index++] = row_y;
			state->output[index++] = column_x;
			state->output[index++] = tile;
			state->output[index++] = state->attributes;
			state->attributes ^= 0x20;
			column_x = (port_u8)(column_x + 8);
		}
		tile = (port_u8)(tile + 2);
		row_y = (port_u8)(row_y + 8);
	}
	state->base_tile = tile;
	hl = (port_u16)(hl + 16);
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.a = row_y;
	state->registers.b = row_y;
	state->registers.c = original_c;
	state->registers.d = 0;
	state->registers.e = 2;
	wide = (port_u16)(port_u8)(original_b + 8) + 8;
	state->registers.f = PORT_FLAG_Z | PORT_FLAG_N;
	if (wide > 0xff)
		state->registers.f |= PORT_FLAG_C;
}

__attribute__((noinline, used)) port_u8
port_load_town_map_entry_begin(struct town_map_entry_state *state)
{
	town_map_cp(&state->registers, 0x25);
	if (state->registers.a < 0x25) {
		state->registers.h = 0x53;
		state->registers.l = 0x13;
		state->registers.c = state->registers.a;
		state->registers.b = 0;
		town_map_add_hl(&state->registers, state->registers.c);
		town_map_add_hl(&state->registers, state->registers.c);
		town_map_add_hl(&state->registers, state->registers.c);
		return 1;
	}
	state->registers.b = 0;
	state->registers.c = 4;
	state->registers.h = 0x53;
	state->registers.l = 0x82;
	return 0;
}

__attribute__((noinline, used)) port_u8
port_load_town_map_entry_scan_step(struct town_map_entry_state *state)
{
	port_u16 hl;

	town_map_cp(&state->registers, state->fetched_compare);
	if (state->registers.a < state->fetched_compare) {
		hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		hl++;
		state->registers.h = (port_u8)(hl >> 8);
		state->registers.l = (port_u8)hl;
		return 1;
	}
	town_map_add_hl(&state->registers, (port_u16)(
		((port_u16)state->registers.b << 8) | state->registers.c));
	return 0;
}

__attribute__((noinline, used)) void
port_load_town_map_entry_finish(struct town_map_entry_state *state)
{
	state->registers.a = state->fetched_coordinate;
	state->written = state->registers.a;
	state->registers.a = state->fetched_name_low;
	state->registers.h = state->fetched_name_high;
	state->registers.l = state->registers.a;
}

/* Port of LoadTownMapEntry in engine/items/town_map.asm. */
__attribute__((noinline, used)) void
port_load_town_map_entry(struct town_map_entry_state *state,
	const port_u8 *memory)
{
	port_u16 hl;
	port_u8 external = port_load_town_map_entry_begin(state);

	if (!external) {
		do {
			hl = (port_u16)(((port_u16)state->registers.h << 8) |
				state->registers.l);
			state->fetched_compare = memory[hl];
		} while (!port_load_town_map_entry_scan_step(state));
	}
	hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	state->fetched_coordinate = memory[hl++];
	state->fetched_name_low = memory[hl++];
	state->fetched_name_high = memory[hl];
	port_load_town_map_entry_finish(state);
}
