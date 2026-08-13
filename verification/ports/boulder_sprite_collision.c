#include "port_state.h"

static port_u16
boulder_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
boulder_cp(struct cpu_register_state *registers, port_u8 right)
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

static port_u8
boulder_next(struct boulder_sprite_collision_state *state)
{
	port_u8 old_c = state->registers.c;
	port_u16 old_hl;
	port_u16 right;
	port_u16 hl;
	unsigned int wide;

	state->registers.c--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (state->registers.c == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_c & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	if (state->registers.c == 0) {
		state->registers.a = 0;
		state->registers.f = PORT_FLAG_Z;
		return 0;
	}
	old_hl = boulder_pair(state->registers.h, state->registers.l);
	right = boulder_pair(state->registers.d, state->registers.e);
	wide = (unsigned int)old_hl + right;
	hl = (port_u16)wide;
	state->registers.f = 0;
	if ((old_hl & 0x0fff) + (right & 0x0fff) > 0x0fff)
		state->registers.f |= PORT_FLAG_H;
	if (wide > 0xffff)
		state->registers.f |= PORT_FLAG_C;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	return 1;
}

__attribute__((noinline, used)) port_u8
port_check_boulder_collision_setup(struct boulder_sprite_collision_state *state)
{
	port_u8 offset = (port_u8)(state->boulder_index - 1);

	offset = (port_u8)((offset << 4) | (offset >> 4));
	state->registers.a = state->boulder_y;
	state->player_y = state->registers.a;
	state->registers.a = state->boulder_x;
	state->player_x = state->registers.a;
	state->registers.a = state->num_sprites;
	state->registers.c = state->registers.a;
	state->registers.d = 0;
	state->registers.e = 15;
	state->registers.h = 0xc2;
	state->registers.l = 0x14;
	state->registers.a = state->facing & 3;
	state->registers.f = PORT_FLAG_H;
	if (state->registers.a == 0)
		state->registers.f |= PORT_FLAG_Z;
	return state->registers.a == 0 ? 2 : 1;
}

/* Returns 1 to continue, 0 for success, or 2 for collision. */
__attribute__((noinline, used)) port_u8
port_check_boulder_collision_vertical_step(
	struct boulder_sprite_collision_state *state)
{
	port_u16 hl = boulder_pair(state->registers.h, state->registers.l);

	hl++;
	state->registers.a = state->player_x;
	boulder_cp(&state->registers, state->sprite_x);
	if (state->registers.a == state->sprite_x) {
		hl--;
		state->registers.a = state->sprite_y;
		hl++;
		state->registers.b = state->registers.a;
		state->registers.a = state->facing;
		state->registers.f = state->registers.a & 1 ? PORT_FLAG_C : 0;
		state->registers.a = state->player_y;
		if (state->facing & 1)
			state->registers.a++;
		else
			state->registers.a--;
		boulder_cp(&state->registers, state->registers.b);
		if (state->registers.a == state->registers.b) {
			state->registers.h = (port_u8)(hl >> 8);
			state->registers.l = (port_u8)hl;
			state->registers.a = 0xff;
			return 2;
		}
	}
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	return boulder_next(state);
}

/* Returns 1 to continue, 0 for success, or 2 for collision. */
__attribute__((noinline, used)) port_u8
port_check_boulder_collision_horizontal_step(
	struct boulder_sprite_collision_state *state)
{
	port_u16 hl = boulder_pair(state->registers.h, state->registers.l);

	state->registers.a = state->sprite_y;
	hl++;
	state->registers.b = state->registers.a;
	state->registers.a = state->player_y;
	boulder_cp(&state->registers, state->registers.b);
	if (state->registers.a == state->registers.b) {
		state->registers.b = state->sprite_x;
		state->registers.a = state->facing;
		state->registers.f = (state->registers.f & PORT_FLAG_C) |
			PORT_FLAG_H;
		if ((state->registers.a & 4) == 0)
			state->registers.f |= PORT_FLAG_Z;
		state->registers.a = state->player_x;
		if (state->facing & 4)
			state->registers.a--;
		else
			state->registers.a++;
		boulder_cp(&state->registers, state->registers.b);
		if (state->registers.a == state->registers.b) {
			state->registers.h = (port_u8)(hl >> 8);
			state->registers.l = (port_u8)hl;
			state->registers.a = 0xff;
			return 2;
		}
	}
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	return boulder_next(state);
}

/* Port of CheckForBoulderCollisionWithSprites in engine/overworld/player_state.asm. */
__attribute__((noinline, used)) void
port_check_for_boulder_collision_with_sprites(
	struct boulder_sprite_collision_state *state, port_u8 *memory)
{
	port_u8 orientation = port_check_boulder_collision_setup(state);
	port_u8 continuation;
	port_u16 pointer;

	do {
		pointer = boulder_pair(state->registers.h, state->registers.l);
		state->sprite_y = memory[pointer];
		state->sprite_x = memory[(port_u16)(pointer + 1)];
		if (orientation == 1)
			continuation = port_check_boulder_collision_vertical_step(state);
		else
			continuation = port_check_boulder_collision_horizontal_step(state);
	} while (continuation == 1);
}
