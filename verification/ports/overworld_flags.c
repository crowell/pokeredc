#include "port_state.h"

static void
bike_cp(struct cpu_register_state *registers, port_u8 right)
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
bike_scf(struct cpu_register_state *registers)
{
	registers->f = (registers->f & PORT_FLAG_Z) | PORT_FLAG_C;
}

__attribute__((noinline, used)) port_u8
port_is_bike_riding_allowed_begin(struct bike_allowed_state *state)
{
	state->registers.a = state->current_map;
	bike_cp(&state->registers, 0x22);
	if (state->registers.a == 0x22) {
		bike_scf(&state->registers);
		return 1;
	}
	bike_cp(&state->registers, 0x09);
	if (state->registers.a == 0x09) {
		bike_scf(&state->registers);
		return 1;
	}
	state->registers.a = state->current_tileset;
	state->registers.b = state->registers.a;
	state->registers.h = 0x09;
	state->registers.l = 0xe2;
	return 0;
}

__attribute__((noinline, used)) port_u8
port_is_bike_riding_allowed_step(struct bike_allowed_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 old_a;

	state->registers.a = state->fetched;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	bike_cp(&state->registers, state->registers.b);
	if (state->registers.a == state->registers.b) {
		bike_scf(&state->registers);
		return 1;
	}
	old_a = state->registers.a;
	state->registers.a++;
	state->registers.f &= PORT_FLAG_C;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_a & 0x0f) == 0x0f)
		state->registers.f |= PORT_FLAG_H;
	if (state->registers.a != 0)
		return 0;
	state->registers.f = PORT_FLAG_Z | PORT_FLAG_H;
	return 2;
}

/* Port of IsBikeRidingAllowed in home/overworld.asm. */
__attribute__((noinline, used)) void
port_is_bike_riding_allowed(
	struct bike_allowed_state *state, const port_u8 *memory)
{
	port_u16 hl;
	port_u8 result = port_is_bike_riding_allowed_begin(state);

	while (result == 0) {
		hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		state->fetched = memory[hl];
		result = port_is_bike_riding_allowed_step(state);
	}
}

static void
coords_inc_a(struct cpu_register_state *registers)
{
	port_u8 old_a = registers->a;

	registers->a++;
	registers->f &= PORT_FLAG_C;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old_a & 0x0f) == 0x0f)
		registers->f |= PORT_FLAG_H;
}

static void
coords_dec_a(struct cpu_register_state *registers)
{
	port_u8 old_a = registers->a;

	registers->a--;
	registers->f &= PORT_FLAG_C;
	registers->f |= PORT_FLAG_N;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old_a & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

/* Port of CheckIfCoordsInFrontOfPlayerMatch in engine/overworld/hidden_events.asm. */
__attribute__((noinline, used)) void
port_check_if_coords_in_front_of_player_match(
	struct coords_front_match_state *state)
{
	state->registers.a = state->facing;
	bike_cp(&state->registers, 4);
	if (state->registers.a == 4) {
		state->registers.a = state->y;
		coords_dec_a(&state->registers);
		bike_cp(&state->registers, state->registers.b);
		if (state->registers.a != state->registers.b)
			goto no_match;
		state->registers.a = state->x;
		bike_cp(&state->registers, state->registers.c);
		if (state->registers.a != state->registers.c)
			goto no_match;
		goto matched;
	}
	bike_cp(&state->registers, 8);
	if (state->registers.a == 8) {
		state->registers.a = state->x;
		coords_dec_a(&state->registers);
		bike_cp(&state->registers, state->registers.c);
		if (state->registers.a != state->registers.c)
			goto no_match;
		state->registers.a = state->y;
		bike_cp(&state->registers, state->registers.b);
		if (state->registers.a != state->registers.b)
			goto no_match;
		goto matched;
	}
	bike_cp(&state->registers, 12);
	if (state->registers.a == 12) {
		state->registers.a = state->x;
		coords_inc_a(&state->registers);
		bike_cp(&state->registers, state->registers.c);
		if (state->registers.a != state->registers.c)
			goto no_match;
		state->registers.a = state->y;
		bike_cp(&state->registers, state->registers.b);
		if (state->registers.a != state->registers.b)
			goto no_match;
		goto matched;
	}
	state->registers.a = state->y;
	coords_inc_a(&state->registers);
	bike_cp(&state->registers, state->registers.b);
	if (state->registers.a != state->registers.b)
		goto no_match;
	state->registers.a = state->x;
	bike_cp(&state->registers, state->registers.c);
	if (state->registers.a != state->registers.c)
		goto no_match;
matched:
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	goto done;
no_match:
	state->registers.a = 0xff;
done:
	state->output = state->registers.a;
}

/* Port of _GetTileAndCoordsInFrontOfPlayer in engine/overworld/player_state.asm. */
__attribute__((noinline, used)) void
port_get_tile_and_coords_in_front_of_player(struct tile_front_state *state)
{
	state->registers.a = state->y;
	state->registers.d = state->registers.a;
	state->registers.a = state->x;
	state->registers.e = state->registers.a;
	state->registers.a = state->facing;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if (state->registers.a == 0) {
		state->registers.a = state->tile_down;
		state->registers.d++;
		state->registers.f &= PORT_FLAG_C;
		if (state->registers.d == 0)
			state->registers.f |= PORT_FLAG_Z;
		if ((state->registers.d & 0x0f) == 0)
			state->registers.f |= PORT_FLAG_H;
	} else {
		bike_cp(&state->registers, 4);
		if (state->registers.a == 4) {
			state->registers.a = state->tile_up;
			state->registers.d--;
			state->registers.f = PORT_FLAG_N;
			if (state->registers.d == 0)
				state->registers.f |= PORT_FLAG_Z;
			if ((state->registers.d & 0x0f) == 0x0f)
				state->registers.f |= PORT_FLAG_H;
		} else {
			bike_cp(&state->registers, 8);
			if (state->registers.a == 8) {
				state->registers.a = state->tile_left;
				state->registers.e--;
				state->registers.f = PORT_FLAG_N;
				if (state->registers.e == 0)
					state->registers.f |= PORT_FLAG_Z;
				if ((state->registers.e & 0x0f) == 0x0f)
					state->registers.f |= PORT_FLAG_H;
			} else {
				bike_cp(&state->registers, 12);
				if (state->registers.a == 12) {
					state->registers.a = state->tile_right;
					state->registers.e++;
					state->registers.f &= PORT_FLAG_C;
					if (state->registers.e == 0)
						state->registers.f |= PORT_FLAG_Z;
					if ((state->registers.e & 0x0f) == 0)
						state->registers.f |= PORT_FLAG_H;
				}
			}
		}
	}
	state->registers.c = state->registers.a;
	state->output = state->registers.a;
}

static void
split_sla_a(struct cpu_register_state *registers)
{
	port_u8 old_a = registers->a;

	registers->a = (port_u8)(old_a << 1);
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old_a & 0x80) != 0)
		registers->f |= PORT_FLAG_C;
}

static void
split_add_l(struct cpu_register_state *registers)
{
	port_u8 old_a = registers->a;
	port_u8 right = registers->l;
	port_u16 result = (port_u16)old_a + right;

	registers->a = (port_u8)result;
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old_a & 0x0f) + (right & 0x0f) > 0x0f)
		registers->f |= PORT_FLAG_H;
	if (result > 0xff)
		registers->f |= PORT_FLAG_C;
}

/* Port of GetSplitMapSpriteSetID in engine/overworld/map_sprites.asm. */
__attribute__((noinline, used)) void
port_get_split_map_sprite_set_id(struct split_sprite_set_state *state)
{
	port_u8 old_a;

	bike_cp(&state->registers, 0xf8);
	if (state->registers.a == 0xf8) {
		state->registers.h = 0xd3;
		state->registers.l = 0x62;
		state->registers.a = state->x;
		bike_cp(&state->registers, 43);
		state->registers.a = 1;
		if ((state->registers.f & PORT_FLAG_C) != 0)
			return;
		state->registers.a = state->x;
		bike_cp(&state->registers, 62);
		state->registers.a = 10;
		if ((state->registers.f & PORT_FLAG_C) == 0)
			return;
		state->registers.a = state->x;
		bike_cp(&state->registers, 55);
		state->registers.b = 8;
		if ((state->registers.f & PORT_FLAG_C) != 0)
			state->registers.b = 13;
		state->registers.a = state->y;
		bike_cp(&state->registers, state->registers.b);
		state->registers.a = 10;
		if ((state->registers.f & PORT_FLAG_C) != 0)
			return;
		state->registers.a = 1;
		return;
	}

	state->registers.h = 0x7a;
	state->registers.l = 0x89;
	state->registers.a &= 0x0f;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	old_a = state->registers.a;
	state->registers.a--;
	state->registers.f = PORT_FLAG_N;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_a & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	split_sla_a(&state->registers);
	split_sla_a(&state->registers);
	split_add_l(&state->registers);
	state->registers.l = state->registers.a;
	if ((state->registers.f & PORT_FLAG_C) != 0) {
		old_a = state->registers.h;
		state->registers.h++;
		state->registers.f = PORT_FLAG_C;
		if (state->registers.h == 0)
			state->registers.f |= PORT_FLAG_Z;
		if ((old_a & 0x0f) == 0x0f)
			state->registers.f |= PORT_FLAG_H;
	}
	state->registers.a = state->direction;
	state->registers.l++;
	bike_cp(&state->registers, 1);
	state->registers.a = state->dividing_line;
	state->registers.l++;
	state->registers.b = state->registers.a;
	state->registers.a = state->direction == 1 ? state->x : state->y;
	bike_cp(&state->registers, state->registers.b);
	if ((state->registers.f & PORT_FLAG_C) == 0) {
		port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
			state->registers.l);
		hl++;
		state->registers.h = (port_u8)(hl >> 8);
		state->registers.l = (port_u8)hl;
		state->registers.a = state->second_set;
	} else {
		state->registers.a = state->first_set;
	}
}

static void
tile_add_a(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 old_a = registers->a;
	port_u16 result = (port_u16)old_a + right;

	registers->a = (port_u8)result;
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old_a & 0x0f) + (right & 0x0f) > 0x0f)
		registers->f |= PORT_FLAG_H;
	if (result > 0xff)
		registers->f |= PORT_FLAG_C;
}

static void
tile_srl_a(struct cpu_register_state *registers)
{
	port_u8 old_a = registers->a;

	registers->a >>= 1;
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old_a & 1) != 0)
		registers->f |= PORT_FLAG_C;
}

static void
tile_add_hl(struct cpu_register_state *registers, port_u16 right)
{
	port_u16 left = (port_u16)(((port_u16)registers->h << 8) | registers->l);
	unsigned long result = (unsigned long)left + right;

	registers->f &= PORT_FLAG_Z;
	if ((left & 0x0fff) + (right & 0x0fff) > 0x0fff)
		registers->f |= PORT_FLAG_H;
	if (result > 0xffff)
		registers->f |= PORT_FLAG_C;
	registers->h = (port_u8)(result >> 8);
	registers->l = (port_u8)result;
}

/* Port of GetTileSpriteStandsOn in engine/overworld/movement.asm. */
__attribute__((noinline, used)) void
port_get_tile_sprite_stands_on(struct tile_sprite_stands_on_state *state)
{
	port_u16 hl;
	port_u8 old_l;

	state->registers.h = 0xc1;
	state->registers.a = state->current_sprite_offset;
	tile_add_a(&state->registers, 4);
	state->registers.l = state->registers.a;
	state->registers.a = state->y_pixels;
	hl = (port_u16)(((port_u16)state->registers.h << 8) | state->registers.l);
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	tile_add_a(&state->registers, 4);
	state->registers.a &= 0xf0;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	tile_srl_a(&state->registers);
	state->registers.c = state->registers.a;
	state->registers.b = 0;
	old_l = state->registers.l;
	state->registers.l++;
	state->registers.f &= PORT_FLAG_C;
	if (state->registers.l == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_l & 0x0f) == 0x0f)
		state->registers.f |= PORT_FLAG_H;
	state->registers.a = state->x_pixels;
	tile_srl_a(&state->registers);
	tile_srl_a(&state->registers);
	tile_srl_a(&state->registers);
	tile_add_a(&state->registers, 20);
	state->registers.d = 0;
	state->registers.e = state->registers.a;
	state->registers.h = 0xc3;
	state->registers.l = 0xa0;
	for (old_l = 0; old_l < 5; old_l++)
		tile_add_hl(&state->registers, state->registers.c);
	tile_add_hl(&state->registers, state->registers.e);
}

__attribute__((noinline, used)) port_u8
port_is_player_standing_on_warp_begin(struct standing_on_warp_state *state)
{
	state->registers.a = state->number_of_warps;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if (state->registers.a == 0)
		return 1;
	state->registers.c = state->registers.a;
	state->registers.h = 0xd3;
	state->registers.l = 0xaf;
	return 0;
}

__attribute__((noinline, used)) port_u8
port_is_player_standing_on_warp_step(struct standing_on_warp_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 old_c;

	state->registers.a = state->y;
	bike_cp(&state->registers, state->fetched_y);
	if (state->registers.a != state->fetched_y) {
		hl = (port_u16)(hl + 4);
		goto next;
	}
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.a = state->x;
	bike_cp(&state->registers, state->fetched_x);
	if (state->registers.a != state->fetched_x) {
		hl = (port_u16)(hl + 3);
		goto next;
	}
	hl++;
	state->registers.a = state->fetched_warp;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->destination_warp = state->registers.a;
	state->registers.a = state->fetched_map;
	state->destination_map = state->registers.a;
	state->registers.h = 0xd7;
	state->registers.l = 0x36;
	state->movement_flags |= 4;
	return 1;
next:
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	old_c = state->registers.c;
	state->registers.c--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_c & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	return state->registers.c == 0;
}

/* Port of IsPlayerStandingOnWarp in engine/overworld/player_state.asm. */
__attribute__((noinline, used)) void
port_is_player_standing_on_warp(
	struct standing_on_warp_state *state, const port_u8 *records)
{
	port_u16 index = 0;

	if (port_is_player_standing_on_warp_begin(state))
		return;
	for (;;) {
		state->fetched_y = records[index];
		state->fetched_x = records[index + 1];
		state->fetched_warp = records[index + 2];
		state->fetched_map = records[index + 3];
		if (port_is_player_standing_on_warp_step(state))
			return;
		index = (port_u16)(index + 4);
	}
}

__attribute__((noinline, used)) void
port_is_player_standing_on_warp_pad_or_hole_begin(
	struct warp_pad_hole_state *state)
{
	state->registers.b = 0;
	state->registers.h = 0x47;
	state->registers.l = 0xa9;
	state->registers.a = state->current_tileset;
	state->registers.c = state->registers.a;
}

__attribute__((noinline, used)) port_u8
port_is_player_standing_on_warp_pad_or_hole_step(
	struct warp_pad_hole_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);

	state->registers.a = state->fetched_tileset;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	bike_cp(&state->registers, 0xff);
	if (state->registers.a == 0xff)
		return 1;
	bike_cp(&state->registers, state->registers.c);
	if (state->registers.a != state->registers.c) {
		hl = (port_u16)(hl + 2);
		state->registers.h = (port_u8)(hl >> 8);
		state->registers.l = (port_u8)hl;
		return 0;
	}
	state->registers.a = state->coordinate_tile;
	bike_cp(&state->registers, state->fetched_tile);
	if (state->registers.a != state->fetched_tile) {
		hl = (port_u16)(hl + 2);
		state->registers.h = (port_u8)(hl >> 8);
		state->registers.l = (port_u8)hl;
		return 0;
	}
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.b = state->fetched_value;
	return 1;
}

__attribute__((noinline, used)) void
port_is_player_standing_on_warp_pad_or_hole_finish(
	struct warp_pad_hole_state *state)
{
	state->registers.a = state->registers.b;
	state->standing_value = state->registers.a;
}

/* Port of IsPlayerStandingOnWarpPadOrHole in player_animations.asm. */
__attribute__((noinline, used)) void
port_is_player_standing_on_warp_pad_or_hole(
	struct warp_pad_hole_state *state, const port_u8 *records)
{
	port_u16 index = 0;

	port_is_player_standing_on_warp_pad_or_hole_begin(state);
	for (;;) {
		state->fetched_tileset = records[index];
		if (state->fetched_tileset != 0xff) {
			state->fetched_tile = records[index + 1];
			state->fetched_value = records[index + 2];
		}
		if (port_is_player_standing_on_warp_pad_or_hole_step(state))
			break;
		index = (port_u16)(index + 3);
	}
	port_is_player_standing_on_warp_pad_or_hole_finish(state);
}

/* Port of GetCutOrBoulderDustAnimationOffsets in engine/overworld/cut.asm. */
__attribute__((noinline, used)) void
port_get_cut_or_boulder_dust_animation_offsets(
	struct dust_animation_offsets_state *state)
{
	port_u16 hl;

	state->registers.h = 0xc1;
	state->registers.l = 0x04;
	state->registers.a = state->y_pixels;
	state->registers.l++;
	state->registers.b = state->registers.a;
	state->registers.l++;
	state->registers.a = state->x_pixels;
	state->registers.l++;
	state->registers.c = state->registers.a;
	state->registers.l++;
	state->registers.l++;
	state->registers.a = state->direction;
	tile_srl_a(&state->registers);
	state->registers.e = state->registers.a;
	state->registers.d = 0;
	state->registers.a = state->which_offsets;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.h = 0x70;
	state->registers.l = state->registers.a == 0 ? 0x8f : 0x97;
	tile_add_hl(&state->registers, state->registers.e);
	state->registers.e = state->fetched_x_offset;
	hl = (port_u16)(((port_u16)state->registers.h << 8) | state->registers.l);
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.d = state->fetched_y_offset;
	state->registers.a = state->registers.b;
	tile_add_a(&state->registers, state->registers.d);
	state->registers.b = state->registers.a;
	state->registers.a = state->registers.c;
	tile_add_a(&state->registers, state->registers.e);
	state->registers.c = state->registers.a;
}

/* Port of GetMoveBoulderDustFunctionPointer in dust_smoke.asm. */
__attribute__((noinline, used)) void
port_get_move_boulder_dust_function_pointer(
	struct boulder_dust_pointer_state *state)
{
	port_u16 hl;
	port_u16 function_pointer;

	state->registers.a = state->facing_direction;
	state->registers.h = 0x5f;
	state->registers.l = 0xb0;
	state->registers.c = state->registers.a;
	state->registers.b = 0;
	tile_add_hl(&state->registers, state->registers.c);
	state->registers.a = state->fetched_adjustment;
	hl = (port_u16)(((port_u16)state->registers.h << 8) | state->registers.l);
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->coordinate_adjustment = state->registers.a;
	state->registers.a = state->fetched_oam_offset;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.e = state->registers.a;
	state->registers.a = state->fetched_pointer_low;
	hl++;
	state->registers.h = state->fetched_pointer_high;
	state->registers.l = state->registers.a;
	function_pointer = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	state->registers.h = 0xc3;
	state->registers.l = 0x90;
	state->registers.d = 0;
	tile_add_hl(&state->registers, state->registers.e);
	state->registers.e = state->registers.l;
	state->registers.d = state->registers.h;
	state->registers.h = (port_u8)(function_pointer >> 8);
	state->registers.l = (port_u8)function_pointer;
}

/* Port of GetTileTwoStepsInFrontOfPlayer in player_state.asm. */
__attribute__((noinline, used)) void
port_get_tile_two_steps_in_front_of_player(struct tile_two_steps_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->player_facing_bits = state->registers.a;
	state->registers.h = 0xd3;
	state->registers.l = 0x61;
	state->registers.a = state->y;
	state->registers.l++;
	state->registers.d = state->registers.a;
	state->registers.e = state->x;
	state->registers.a = state->facing;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if (state->registers.a == 0) {
		state->registers.h = 0xff;
		state->registers.l = 0xdb;
		state->player_facing_bits |= 1;
		state->registers.a = state->tile_down;
		state->registers.d++;
		state->registers.f = 0;
		if (state->registers.d == 0)
			state->registers.f |= PORT_FLAG_Z;
		if ((state->registers.d & 0x0f) == 0)
			state->registers.f |= PORT_FLAG_H;
	} else {
		bike_cp(&state->registers, 4);
		if (state->registers.a == 4) {
			state->registers.h = 0xff;
			state->registers.l = 0xdb;
			state->player_facing_bits |= 2;
			state->registers.a = state->tile_up;
			state->registers.d--;
			state->registers.f = PORT_FLAG_N;
			if (state->registers.d == 0)
				state->registers.f |= PORT_FLAG_Z;
			if ((state->registers.d & 0x0f) == 0x0f)
				state->registers.f |= PORT_FLAG_H;
		} else {
			bike_cp(&state->registers, 8);
			if (state->registers.a == 8) {
				state->registers.h = 0xff;
				state->registers.l = 0xdb;
				state->player_facing_bits |= 4;
				state->registers.a = state->tile_left;
				state->registers.e--;
				state->registers.f = PORT_FLAG_N;
				if (state->registers.e == 0)
					state->registers.f |= PORT_FLAG_Z;
				if ((state->registers.e & 0x0f) == 0x0f)
					state->registers.f |= PORT_FLAG_H;
			} else {
				bike_cp(&state->registers, 12);
				if (state->registers.a == 12) {
					state->registers.h = 0xff;
					state->registers.l = 0xdb;
					state->player_facing_bits |= 8;
					state->registers.a = state->tile_right;
					state->registers.e++;
					state->registers.f = 0;
					if (state->registers.e == 0)
						state->registers.f |= PORT_FLAG_Z;
					if ((state->registers.e & 0x0f) == 0)
						state->registers.f |= PORT_FLAG_H;
				}
			}
		}
	}
	state->registers.c = state->registers.a;
	state->collision_result = state->registers.a;
	state->tile_in_front = state->registers.a;
}

/* Port of CheckPlayerIsInFrontOfSprite in trainer_sight.asm. */
__attribute__((noinline, used)) void
port_check_player_is_in_front_of_sprite(struct trainer_front_state *state)
{
	state->registers.a = state->current_map;
	bike_cp(&state->registers, 0x53);
	if (state->registers.a == 0x53)
		goto engage;
	state->registers.a = state->trainer_offset;
	tile_add_a(&state->registers, 4);
	state->registers.d = 0;
	state->registers.e = state->registers.a;
	state->registers.h = 0xc1;
	state->registers.l = 0;
	tile_add_hl(&state->registers, state->registers.e);
	state->registers.a = state->fetched_y;
	bike_cp(&state->registers, 0xfc);
	if (state->registers.a == 0xfc)
		state->registers.a = 0x0c;
	state->trainer_screen_y = state->registers.a;
	state->registers.a = state->trainer_offset;
	tile_add_a(&state->registers, 6);
	state->registers.d = 0;
	state->registers.e = state->registers.a;
	state->registers.h = 0xc1;
	state->registers.l = 0;
	tile_add_hl(&state->registers, state->registers.e);
	state->registers.a = state->fetched_x;
	state->trainer_screen_x = state->registers.a;
	state->registers.a = state->trainer_facing;
	bike_cp(&state->registers, 0);
	if (state->registers.a == 0) {
		state->registers.a = state->trainer_screen_y;
		bike_cp(&state->registers, 0x3c);
		if (state->registers.a < 0x3c)
			goto engage;
		goto no_engage;
	}
	bike_cp(&state->registers, 4);
	if (state->registers.a == 4) {
		state->registers.a = state->trainer_screen_y;
		bike_cp(&state->registers, 0x3c);
		if (state->registers.a >= 0x3c)
			goto engage;
		goto no_engage;
	}
	bike_cp(&state->registers, 8);
	state->registers.a = state->trainer_screen_x;
	bike_cp(&state->registers, 0x40);
	if (state->trainer_facing == 8) {
		if (state->registers.a >= 0x40)
			goto engage;
		goto no_engage;
	}
	if (state->registers.a >= 0x40)
		goto no_engage;
engage:
	state->registers.a = 0xff;
	goto done;
no_engage:
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
done:
	state->trainer_offset = state->registers.a;
}

static void
sprite_screen_sub(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;

	registers->a = (port_u8)(left - right);
	registers->f = PORT_FLAG_N;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
}

static void
sprite_screen_swap_a(struct cpu_register_state *registers)
{
	registers->a = (port_u8)((registers->a << 4) | (registers->a >> 4));
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
}

/* Port of InitializeSpriteScreenPosition in engine/overworld/movement.asm. */
__attribute__((noinline, used)) void
port_initialize_sprite_screen_position(struct init_sprite_screen_state *state)
{
	port_u16 hl;
	port_u8 old_h;

	state->registers.h = 0xc2;
	state->registers.a = state->current_offset;
	tile_add_a(&state->registers, 4);
	state->registers.l = state->registers.a;
	state->registers.a = state->player_y;
	state->registers.b = state->registers.a;
	state->registers.a = state->map_y;
	sprite_screen_sub(&state->registers, state->registers.b);
	sprite_screen_swap_a(&state->registers);
	sprite_screen_sub(&state->registers, 4);
	state->registers.h--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	state->screen_y = state->registers.a;
	hl = (port_u16)(((port_u16)state->registers.h << 8) | state->registers.l);
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	old_h = state->registers.h;
	state->registers.h++;
	state->registers.f &= PORT_FLAG_C;
	if (state->registers.h == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_h & 0x0f) == 0x0f)
		state->registers.f |= PORT_FLAG_H;
	state->registers.a = state->player_x;
	state->registers.b = state->registers.a;
	state->registers.a = state->map_x;
	hl = (port_u16)(((port_u16)state->registers.h << 8) | state->registers.l);
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	sprite_screen_sub(&state->registers, state->registers.b);
	sprite_screen_swap_a(&state->registers);
	state->registers.h--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	state->screen_x = state->registers.a;
}

/* Port of SetSpriteCollisionValues in sprite_collisions.asm. */
__attribute__((noinline, used)) void
port_set_sprite_collision_values(struct cpu_register_state *registers)
{
	registers->f = PORT_FLAG_H;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	registers->b = 0;
	registers->c = 0;
	if (registers->a == 0)
		return;
	registers->c = 9;
	bike_cp(registers, 0xff);
	if (registers->a == 0xff) {
		registers->b = registers->a;
		return;
	}
	registers->c = 7;
	registers->a = 0;
	registers->b = registers->a;
}

/* Port of UpdateSpriteFacingOffsetAndDelayMovement in turn_sprite.asm. */
__attribute__((noinline, used)) void
port_update_sprite_facing_offset_and_delay_movement(
	struct sprite_facing_delay_state *state)
{
	port_u16 hl;

	state->registers.h = 0xc2;
	state->registers.a = state->current_offset;
	tile_add_a(&state->registers, 8);
	state->registers.l = state->registers.a;
	state->registers.a = 0x7f;
	state->movement_delay = state->registers.a;
	state->registers.h--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	state->registers.a = state->current_offset;
	tile_add_a(&state->registers, 9);
	state->registers.l = state->registers.a;
	state->registers.a = state->facing_direction;
	hl = (port_u16)(((port_u16)state->registers.h << 8) | state->registers.l);
	hl--;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.b = state->registers.a;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->animation_frame = state->registers.a;
	hl--;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->intra_animation_frame = state->registers.a;
	state->registers.a = state->current_offset;
	tile_add_a(&state->registers, 2);
	state->registers.l = state->registers.a;
	state->registers.a = state->image_index;
	state->registers.a |= state->registers.b;
	state->registers.f = 0;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->image_index = state->registers.a;
	hl = (port_u16)(((port_u16)state->registers.h << 8) | state->registers.l);
	hl--;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.a = 2;
	state->movement_status = state->registers.a;
}

/* Port of UpdateSpriteImage in engine/overworld/movement.asm. */
__attribute__((noinline, used)) void
port_update_sprite_image(struct update_sprite_image_state *state)
{
	port_u16 hl;

	state->registers.h = 0xc1;
	state->registers.a = state->current_offset;
	tile_add_a(&state->registers, 8);
	state->registers.l = state->registers.a;
	state->registers.a = state->animation_frame;
	hl = (port_u16)(((port_u16)state->registers.h << 8) | state->registers.l);
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.b = state->registers.a;
	state->registers.a = state->facing_direction;
	tile_add_a(&state->registers, state->registers.b);
	state->registers.b = state->registers.a;
	state->registers.a = state->player_tile;
	tile_add_a(&state->registers, state->registers.b);
	state->registers.b = state->registers.a;
	state->registers.a = state->current_offset;
	tile_add_a(&state->registers, 2);
	state->registers.l = state->registers.a;
	state->image_index = state->registers.b;
}

static port_u16
sprite_status_address(port_u16 initial, port_u8 offset, port_u8 index)
{
	port_u8 h = (port_u8)(initial >> 8);
	port_u8 l = (port_u8)initial;

	if (index == 0)
		return initial;
	if (index == 1)
		return (port_u16)(((port_u16)h << 8) | (port_u8)(l + 1));
	h++;
	l = (port_u8)(offset + 2);
	initial = (port_u16)(((port_u16)h << 8) | l);
	return (port_u16)(initial + (index == 3));
}

static void
sprite_status_store(struct init_sprite_status_state *state,
	port_u16 initial, port_u8 offset, port_u16 address, port_u8 value)
{
	port_u8 index;

	for (index = 0; index != 4; index++)
		if (sprite_status_address(initial, offset, index) == address)
			state->memory[index] = value;
}

/* Port of InitializeSpriteStatus in engine/overworld/movement.asm. */
__attribute__((noinline, used)) void
port_initialize_sprite_status(struct init_sprite_status_state *state)
{
	port_u16 initial = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u8 old_a;
	port_u8 l;
	port_u16 address;

	sprite_status_store(state, initial, state->current_offset, initial, 1);
	state->registers.l++;
	address = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	sprite_status_store(state, initial, state->current_offset, address, 0xff);
	state->registers.h++;
	state->registers.a = state->current_offset;
	old_a = state->registers.a;
	state->registers.a = (port_u8)(state->registers.a + 2);
	state->registers.f = 0;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_a & 0x0f) + 2 > 0x0f)
		state->registers.f |= PORT_FLAG_H;
	if ((port_u16)old_a + 2 > 0xff)
		state->registers.f |= PORT_FLAG_C;
	state->registers.l = state->registers.a;
	state->registers.a = 8;
	l = state->registers.l;
	address = (port_u16)(((port_u16)state->registers.h << 8) | l);
	sprite_status_store(state, initial, state->current_offset, address, 8);
	address++;
	state->registers.h = (port_u8)(address >> 8);
	state->registers.l = (port_u8)address;
	sprite_status_store(state, initial, state->current_offset, address, 8);
}

/* Port of IsPlayerCharacterBeingControlledByGame in home/npc_movement.asm. */
__attribute__((noinline, used)) void
port_is_player_character_being_controlled_by_game(
	struct player_control_state *state)
{
	state->registers.a = state->npc_script;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a != 0)
		return;
	state->registers.f |= PORT_FLAG_Z;
	state->registers.a = state->movement_flags;
	state->registers.f = PORT_FLAG_H;
	if ((state->registers.a & 0x02) != 0)
		return;
	state->registers.f |= PORT_FLAG_Z;
	state->registers.a = state->status_flags5 & 0x80;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
}

/* Port of ResetBoulderPushFlags in engine/overworld/push_boulder.asm. */
__attribute__((noinline, used)) void
port_reset_boulder_push_flags(struct misc_flags_state *state)
{
	state->registers.h = 0xcd;
	state->registers.l = 0x60;
	state->misc_flags &= (port_u8)~(0x02 | 0x40);
}

/* Port of SetSpriteImageIndexAfterSettingFacingDirection. */
__attribute__((noinline, used)) void
port_set_sprite_image_index_after_setting_facing_direction(
	struct pointer_store_state *state)
{
	port_u16 hl = ((port_u16)state->registers.h << 8) | state->registers.l;
	unsigned long wide = (unsigned long)hl + 0xfff9;
	port_u8 flags = state->registers.f & PORT_FLAG_Z;

	state->registers.d = 0xff;
	state->registers.e = 0xf9;
	if ((hl & 0x0fff) + 0x0ff9 > 0x0fff)
		flags |= PORT_FLAG_H;
	if (wide > 0xffff)
		flags |= PORT_FLAG_C;
	state->registers.f = flags;
	state->registers.h = (port_u8)(wide >> 8);
	state->registers.l = (port_u8)wide;
	state->destination = state->registers.a;
}

/* Port of OverwritewMoves in home/pokemon.asm. */
__attribute__((noinline, used)) void
port_overwrite_w_moves(struct pointer_store_state *state)
{
	port_u16 hl = 0xd0dc;
	port_u16 offset = state->registers.b;
	unsigned long wide;
	port_u8 flags = state->registers.f & PORT_FLAG_Z;

	state->registers.h = 0xd0;
	state->registers.l = 0xdc;
	state->registers.e = state->registers.b;
	state->registers.d = 0;
	wide = (unsigned long)hl + offset;
	if ((hl & 0x0fff) + offset > 0x0fff)
		flags |= PORT_FLAG_H;
	if (wide > 0xffff)
		flags |= PORT_FLAG_C;
	state->registers.f = flags;
	state->registers.h = (port_u8)(wide >> 8);
	state->registers.l = (port_u8)wide;
	state->registers.a = state->registers.c;
	state->destination = state->registers.a;
}
