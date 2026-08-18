#include "port_state.h"

/* Port of GetSubanimationTransform1 in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_get_subanimation_transform1(struct subanimation_transform_state *state)
{
	state->registers.b = state->registers.a;
	state->registers.a = state->whose_turn;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.a = state->registers.b;
	if (state->whose_turn == 0) {
		state->registers.a = 0;
		state->registers.f = PORT_FLAG_Z;
	}
}

/* Port of GetSubanimationTransform2 in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_get_subanimation_transform2(struct subanimation_transform_state *state)
{
	state->registers.a = state->whose_turn;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.a = 0x40;
	if (state->whose_turn != 0) {
		state->registers.a = 0;
		state->registers.f = PORT_FLAG_Z;
	}
}

/* Port of IsCryMove in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_is_cry_move(struct cry_move_state *state)
{
	state->registers.a = state->animation_id;
	if (state->registers.a == 0x2d || state->registers.a == 0x2e) {
		state->registers.f = PORT_FLAG_C;
		return;
	}
	state->registers.f = 0;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
}

/* Port of GetMonSpriteTileMapPointerFromRowCount. */
__attribute__((noinline, used)) void
port_get_mon_sprite_tilemap_pointer_from_row_count(
	struct subanimation_transform_state *state)
{
	port_u8 saved_d = state->registers.d;
	port_u8 saved_e = state->registers.e;
	port_u8 rows_to_skip;
	port_u16 hl;

	state->registers.a = state->whose_turn;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.a = state->whose_turn == 0 ? 0x65 : 0x0c;
	hl = 0xc3a0 + state->registers.a;
	state->registers.a = 7 - state->registers.b;
	rows_to_skip = state->registers.a;
	state->registers.f = PORT_FLAG_H;
	if (rows_to_skip == 0) {
		state->registers.f |= PORT_FLAG_Z;
	} else {
		hl += (port_u16)rows_to_skip * 20;
		state->registers.a = 0;
		state->registers.f = PORT_FLAG_Z | PORT_FLAG_N;
	}
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.d = saved_d;
	state->registers.e = saved_e;
}

/* Port of GetTileIDList in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_get_tile_id_list(struct cpu_register_state *registers)
{
	static const port_u16 pointers[8] = {
		0x5b24, 0x5b55, 0x5b78, 0x5b8d,
		0x5bbe, 0x5bef, 0x5c20, 0x5c50,
	};
	static const port_u8 dimensions[8] = {
		0x77, 0x57, 0x37, 0x77, 0x77, 0x77, 0x86, 0x3c,
	};
	port_u8 index = registers->a;
	port_u16 hl = 0x5aea + (port_u16)index * 3;
	port_u8 packed;

	registers->d = (port_u8)(pointers[index] >> 8);
	registers->e = (port_u8)pointers[index];
	packed = dimensions[index];
	registers->c = packed & 0x0f;
	registers->a = packed >> 4;
	registers->b = registers->a;
	registers->h = (port_u8)((hl + 3) >> 8);
	registers->l = (port_u8)(hl + 3);
	registers->f = PORT_FLAG_H;
}

/* Port of AnimCopyRowLeft in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_anim_copy_row_left(struct anim_copy_row_state *state)
{
	port_u8 count = state->registers.c;
	port_u8 i;
	port_u16 hl = ((port_u16)state->registers.h << 8) | state->registers.l;

	for (i = 0; i < count; i++) {
		state->registers.a = state->tiles[i + 1];
		state->tiles[i] = state->registers.a;
	}
	state->registers.c = 0;
	hl += count;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.f =
		(state->registers.f & PORT_FLAG_C) | PORT_FLAG_Z | PORT_FLAG_N;
}

/* Port of AnimCopyRowRight in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_anim_copy_row_right(struct anim_copy_row_state *state)
{
	port_u8 count = state->registers.c;
	port_u8 i;
	port_u16 hl = ((port_u16)state->registers.h << 8) | state->registers.l;

	for (i = count; i != 0; i--) {
		state->registers.a = state->tiles[i - 1];
		state->tiles[i] = state->registers.a;
	}
	state->registers.c = 0;
	hl -= count;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.f =
		(state->registers.f & PORT_FLAG_C) | PORT_FLAG_Z | PORT_FLAG_N;
}

static port_u8
palette_cp_flags(port_u8 left, port_u8 right)
{
	port_u8 result = left - right;
	port_u8 flags = PORT_FLAG_N;

	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		flags |= PORT_FLAG_H;
	if (left < right)
		flags |= PORT_FLAG_C;
	return flags;
}

/* Port of SetAnimationPalette in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_set_animation_palette(struct animation_palette_state *state)
{
	state->registers.a = state->on_sgb;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.a = 0xe4;
	if (state->on_sgb == 0) {
		state->animation_palette = state->registers.a;
		state->object_palette0 = state->registers.a;
		state->registers.a = 0x6c;
		state->object_palette1 = state->registers.a;
		return;
	}

	state->registers.a = 0xf0;
	state->animation_palette = state->registers.a;
	state->registers.b = 0xe4;
	state->registers.a = state->animation_id;
	state->registers.f = palette_cp_flags(state->registers.a, 0xaa);
	if (state->registers.a >= 0xaa) {
		state->registers.f = palette_cp_flags(state->registers.a, 0xae);
		if (state->registers.a < 0xae)
			state->registers.b = 0xf0;
	}
	state->registers.a = state->registers.b;
	state->object_palette0 = state->registers.a;
	state->registers.a = 0x6c;
	state->object_palette1 = state->registers.a;
}

/* Port of FallingObjects_UpdateMovementByte. */
__attribute__((noinline, used)) void
port_falling_objects_update_movement_byte(
	struct falling_object_movement_state *state)
{
	port_u8 masked;

	state->registers.a = state->movement_byte + 1;
	state->registers.b = state->registers.a;
	masked = state->registers.a & 0x7f;
	state->registers.f = palette_cp_flags(masked, 9);
	state->registers.a = state->registers.b;
	if (masked == 9) {
		state->registers.a = (state->registers.a & 0x80) ^ 0x80;
		state->registers.f = 0;
		if (state->registers.a == 0)
			state->registers.f = PORT_FLAG_Z;
	}
	state->movement_byte = state->registers.a;
}

/* Port of ShareMoveAnimations in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_share_move_animations(struct share_move_animation_state *state)
{
	state->registers.a = state->whose_turn;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0) {
		state->registers.f |= PORT_FLAG_Z;
		return;
	}

	state->registers.a = state->animation_id;
	state->registers.f = palette_cp_flags(state->registers.a, 0x85);
	state->registers.b = 0xbf;
	if (state->registers.a == 0x85) {
		state->registers.a = state->registers.b;
		state->animation_id = state->registers.a;
		return;
	}

	state->registers.f = palette_cp_flags(state->registers.a, 0x9c);
	state->registers.b = 0xbd;
	if (state->registers.a == 0x9c) {
		state->registers.a = state->registers.b;
		state->animation_id = state->registers.a;
	}
}

__attribute__((noinline, used)) void
port_call_with_turn_flipped_begin(struct call_with_turn_flipped_state *state)
{
	state->registers.a = state->whose_turn;
	state->saved_a = state->registers.a;
	state->saved_f = state->registers.f;
	state->registers.a ^= 1;
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	state->whose_turn = state->registers.a;
	state->registers.d = 0x51;
	state->registers.e = 0x61;
}

__attribute__((noinline, used)) void
port_call_with_turn_flipped_return(struct call_with_turn_flipped_state *state)
{
	state->registers.a = state->saved_a;
	state->registers.f = state->saved_f;
	state->whose_turn = state->registers.a;
}

/* Port of CallWithTurnFlipped in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_call_with_turn_flipped(struct call_with_turn_flipped_state *state,
	const struct cpu_register_state *callback_registers,
	port_u8 callback_whose_turn)
{
	port_call_with_turn_flipped_begin(state);
	/* The indirect JP target is an explicit compositional boundary. */
	state->registers = *callback_registers;
	state->whose_turn = callback_whose_turn;
	port_call_with_turn_flipped_return(state);
}

static void
select_animation_type(struct memory_predicate_state *state,
	port_u8 no_effect, port_u8 has_effect)
{
	port_u8 effect = state->value;

	state->registers.a = effect;
	state->registers.f = PORT_FLAG_H;
	if (effect == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.a = effect == 0 ? no_effect : has_effect;
}

/* Port of GetPlayerAnimationType through PlayPlayerMoveAnimation. */
__attribute__((noinline, used)) void
port_get_player_animation_type(struct memory_predicate_state *state)
{
	select_animation_type(state, 4, 5);
}

/* Port of GetEnemyAnimationType through PlayEnemyMoveAnimation. */
__attribute__((noinline, used)) void
port_get_enemy_animation_type(struct memory_predicate_state *state)
{
	select_animation_type(state, 1, 2);
}

/* Port of AnimationHideMonPic through ClearMonPicFromTileMap. */
__attribute__((noinline, used)) void
port_animation_hide_mon_pic(struct subanimation_transform_state *state)
{
	state->registers.a = state->whose_turn;
	state->registers.f = PORT_FLAG_H;
	if (state->whose_turn == 0)
		state->registers.f |= PORT_FLAG_Z;
	state->registers.a = state->whose_turn == 0 ? 101 : 12;
}

/* Port of FallingObjects_InitXCoords. */
__attribute__((noinline, used)) void
port_falling_objects_init_x_coords(struct falling_x_init_state *state)
{
	static const port_u8 initial_x[20] = {
		0x38, 0x40, 0x50, 0x60, 0x70, 0x88, 0x90, 0x56, 0x67, 0x4a,
		0x77, 0x84, 0x98, 0x32, 0x22, 0x5c, 0x6c, 0x7d, 0x8e, 0x99,
	};
	port_u8 count = state->num_objects;
	port_u8 i;
	port_u16 hl = 0xc301;
	port_u16 de = 0x5d3e;

	state->registers.a = count;
	state->registers.c = count;
	for (i = 0; i < count; i++) {
		state->registers.a = initial_x[i];
		state->oam[(port_u8)(i * 4)] = state->registers.a;
	}
	state->registers.c = 0;
	hl += (port_u16)count * 4;
	de += count;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	state->registers.f =
		(state->registers.f & PORT_FLAG_C) | PORT_FLAG_Z | PORT_FLAG_N;
}

/* Port of FallingObjects_InitMovementData. */
__attribute__((noinline, used)) void
port_falling_objects_init_movement_data(
	struct falling_movement_init_state *state)
{
	static const port_u8 initial_movement[20] = {
		0x00, 0x84, 0x06, 0x81, 0x02, 0x88, 0x01, 0x83, 0x05, 0x89,
		0x09, 0x80, 0x07, 0x87, 0x03, 0x82, 0x04, 0x85, 0x08, 0x86,
	};
	port_u8 count = state->num_objects;
	port_u8 i;
	port_u16 hl = 0xcd3d;
	port_u16 de = 0x5d63;

	state->registers.a = count;
	state->registers.c = count;
	for (i = 0; i < count; i++) {
		state->registers.a = initial_movement[i];
		state->movement[i] = state->registers.a;
	}
	state->registers.c = 0;
	hl += count;
	de += count;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.d = (port_u8)(de >> 8);
	state->registers.e = (port_u8)de;
	state->registers.f =
		(state->registers.f & PORT_FLAG_C) | PORT_FLAG_Z | PORT_FLAG_N;
}

/* Port of FallingObjects_UpdateOAMEntry. */
__attribute__((noinline, used)) void
port_falling_objects_update_oam_entry(struct falling_oam_update_state *state)
{
	static const port_u8 delta_window[128] = {
		0x00, 0x01, 0x03, 0x05, 0x07, 0x09, 0x0b, 0x0d,
		0x0f, 0xfa, 0x8a, 0xd0, 0x3c, 0x47, 0xe6, 0x7f,
		0xfe, 0x09, 0x78, 0x20, 0x04, 0xe6, 0x80, 0xee,
		0x80, 0xea, 0x8a, 0xd0, 0xc9, 0x21, 0x01, 0xc3,
		0x11, 0x3e, 0x5d, 0xfa, 0x8b, 0xd0, 0x4f, 0x1a,
		0x22, 0x23, 0x23, 0x23, 0x13, 0x0d, 0x20, 0xf7,
		0xc9, 0x38, 0x40, 0x50, 0x60, 0x70, 0x88, 0x90,
		0x56, 0x67, 0x4a, 0x77, 0x84, 0x98, 0x32, 0x22,
		0x5c, 0x6c, 0x7d, 0x8e, 0x99, 0x21, 0x3d, 0xcd,
		0x11, 0x63, 0x5d, 0xfa, 0x8b, 0xd0, 0x4f, 0x1a,
		0x22, 0x13, 0x0d, 0x20, 0xfa, 0xc9, 0x00, 0x84,
		0x06, 0x81, 0x02, 0x88, 0x01, 0x83, 0x05, 0x89,
		0x09, 0x80, 0x07, 0x87, 0x03, 0x82, 0x04, 0x85,
		0x08, 0x86, 0x11, 0x10, 0x93, 0x21, 0x00, 0x80,
		0x01, 0x31, 0x00, 0xcd, 0x48, 0x18, 0xaf, 0xe0,
		0xae, 0x21, 0x00, 0x98, 0xcd, 0x0d, 0x5e, 0x3e,
	};
	port_u16 offset = ((port_u16)state->registers.d << 8) | state->registers.e;
	port_u16 hl = 0xc300 + offset;
	port_u8 index;
	port_u8 delta;
	port_u8 y;

	y = state->oam_entry[0] + 2;
	state->registers.a = y < 112 ? y : 160;
	state->oam_entry[0] = state->registers.a;
	state->registers.a = state->movement_byte;
	state->registers.b = state->registers.a;
	index = state->registers.a & 0x7f;
	delta = delta_window[index];
	state->registers.d = (port_u8)((0x5d0d + index) >> 8);
	state->registers.e = (port_u8)(0x5d0d + index);
	if ((state->registers.b & 0x80) == 0) {
		state->registers.a = delta + state->oam_entry[1];
		state->oam_entry[1] = state->registers.a;
		state->registers.a = 0;
		state->registers.f = PORT_FLAG_Z;
	} else {
		state->registers.b = delta;
		state->registers.a = state->oam_entry[1];
		state->registers.f =
			palette_cp_flags(state->registers.a, state->registers.b);
		state->registers.a -= state->registers.b;
		state->oam_entry[1] = state->registers.a;
		state->registers.a = 0x20;
	}
	state->oam_entry[3] = state->registers.a;
	hl += 3;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
}

static void
adjust_oam_block(struct adjust_oam_block_state *state, port_u8 threshold)
{
	port_u8 count = state->registers.c;
	port_u8 i;
	port_u16 hl =
		((port_u16)state->registers.h << 8) | state->registers.l;

	state->registers.d = 0;
	state->registers.e = 4;
	for (i = 0; i < count; i++) {
		state->registers.a = state->adjustment;
		state->registers.b = state->registers.a;
		state->registers.a =
			(port_u8)(state->oam[1 + i * 4] + state->registers.b);
		if (state->registers.a >= threshold) {
			state->registers.a = 160;
			state->oam[i * 4] = state->registers.a;
		}
		state->oam[1 + i * 4] = state->registers.a;
	}
	state->registers.c = 0;
	hl += (port_u16)count * 4;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.f = PORT_FLAG_Z | PORT_FLAG_N;
}

/* Ports of AdjustOAMBlockXPos2 and its DE-to-HL entry point. */
__attribute__((noinline, used)) void
port_adjust_oam_block_x_pos2(struct adjust_oam_block_state *state)
{
	adjust_oam_block(state, 168);
}

__attribute__((noinline, used)) void
port_adjust_oam_block_x_pos(struct adjust_oam_block_state *state)
{
	state->registers.l = state->registers.e;
	state->registers.h = state->registers.d;
	adjust_oam_block(state, 168);
}

/* Ports of AdjustOAMBlockYPos2 and its DE-to-HL entry point. */
__attribute__((noinline, used)) void
port_adjust_oam_block_y_pos2(struct adjust_oam_block_state *state)
{
	adjust_oam_block(state, 112);
}

__attribute__((noinline, used)) void
port_adjust_oam_block_y_pos(struct adjust_oam_block_state *state)
{
	state->registers.l = state->registers.e;
	state->registers.h = state->registers.d;
	adjust_oam_block(state, 112);
}

/* Port of BattleAnimWriteOAMEntry in engine/battle/animations.asm. */
__attribute__((noinline, used)) void
port_battle_anim_write_oam_entry(struct battle_anim_oam_entry_state *state)
{
	port_u16 hl =
		((port_u16)state->registers.h << 8) | state->registers.l;

	state->registers.a = state->registers.e + 8;
	state->registers.e = state->registers.a;
	state->oam_entry[0] = state->registers.a;
	state->registers.a = state->base_x;
	state->oam_entry[1] = state->registers.a;
	state->registers.a = state->registers.d;
	state->oam_entry[2] = state->registers.a;
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->oam_entry[3] = state->registers.a;
	hl += 4;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
}
