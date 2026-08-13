#include "port_state.h"

static port_u16
front_pair(port_u8 high, port_u8 low)
{
	return (port_u16)(((port_u16)high << 8) | low);
}

static void
front_cp(struct cpu_register_state *registers, port_u8 right)
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
front_add(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;
	unsigned int wide = (unsigned int)left + right;

	registers->a = (port_u8)wide;
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) > 0x0f)
		registers->f |= PORT_FLAG_H;
	if (wide > 0xff)
		registers->f |= PORT_FLAG_C;
}

static void
front_sub(struct cpu_register_state *registers, port_u8 right)
{
	port_u8 left = registers->a;

	registers->a -= right;
	registers->f = PORT_FLAG_N;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
}

static void
front_inc(struct cpu_register_state *registers, port_u8 *value)
{
	port_u8 old = *value;
	port_u8 carry = registers->f & PORT_FLAG_C;

	(*value)++;
	registers->f = carry;
	if (*value == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0x0f)
		registers->f |= PORT_FLAG_H;
}

static void
front_dec(struct cpu_register_state *registers, port_u8 *value)
{
	port_u8 old = *value;
	port_u8 carry = registers->f & PORT_FLAG_C;

	(*value)--;
	registers->f = carry | PORT_FLAG_N;
	if (*value == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

/* Returns 1 when the sprite scan must begin, or 0 for the early return. */
__attribute__((noinline, used)) port_u8
port_is_sprite_in_front_setup(struct sprite_in_front_state *state)
{
	state->registers.b = 0x3c;
	state->registers.c = 0x40;
	state->registers.a = state->facing_direction;
	front_cp(&state->registers, 4);
	if (state->registers.a == 4) {
		state->registers.a = state->registers.b;
		front_sub(&state->registers, state->registers.d);
		state->registers.b = state->registers.a;
		state->registers.a = 8;
	} else {
		front_cp(&state->registers, 0);
		if (state->registers.a == 0) {
			state->registers.a = state->registers.b;
			front_add(&state->registers, state->registers.d);
			state->registers.b = state->registers.a;
			state->registers.a = 4;
		} else {
			front_cp(&state->registers, 12);
			if (state->registers.a == 12) {
				state->registers.a = state->registers.c;
				front_add(&state->registers, state->registers.d);
				state->registers.c = state->registers.a;
				state->registers.a = 1;
			} else {
				state->registers.a = state->registers.c;
				front_sub(&state->registers, state->registers.d);
				state->registers.c = state->registers.a;
				state->registers.a = 2;
			}
		}
	}
	state->player_direction = state->registers.a;
	state->registers.a = state->num_sprites;
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	if (state->registers.a == 0)
		return 0;
	state->registers.h = 0xc1;
	state->registers.l = 0x10;
	state->registers.d = state->registers.a;
	state->registers.e = 1;
	return 1;
}

/* Returns 1 to continue, 0 if none remain, or 2 if this sprite was found. */
__attribute__((noinline, used)) port_u8
port_is_sprite_in_front_step(struct sprite_in_front_state *state)
{
	port_u16 saved_hl = front_pair(state->registers.h, state->registers.l);
	port_u16 hl = saved_hl;

	state->registers.a = state->sprite_image;
	hl++;
	state->registers.f = state->registers.a == 0 ? PORT_FLAG_Z : 0;
	if (state->registers.a != 0) {
		state->registers.l = (port_u8)((port_u8)hl + 1);
		hl = front_pair((port_u8)(hl >> 8), state->registers.l);
		state->registers.a = state->sprite_visibility;
		hl++;
		front_inc(&state->registers, &state->registers.a);
		if (state->registers.a != 0) {
			state->registers.l = (port_u8)((port_u8)hl + 1);
			hl = front_pair((port_u8)(hl >> 8), state->registers.l);
			state->registers.a = state->sprite_y;
			hl++;
			front_cp(&state->registers, state->registers.b);
			if (state->registers.a == state->registers.b) {
				state->registers.l = (port_u8)((port_u8)hl + 1);
				hl = front_pair((port_u8)(hl >> 8), state->registers.l);
				state->registers.a = state->sprite_x;
				front_cp(&state->registers, state->registers.c);
				if (state->registers.a == state->registers.c) {
					state->registers.h = (port_u8)(saved_hl >> 8);
					state->registers.l = (port_u8)saved_hl;
					state->registers.a = state->registers.l & 0xf0;
					state->registers.f = PORT_FLAG_H;
					front_inc(&state->registers, &state->registers.a);
					state->registers.l = state->registers.a;
					state->movement_status |= 0x80;
					state->registers.a = state->registers.e;
					state->text_id = state->registers.a;
					return 2;
				}
			}
		}
	}
	state->registers.h = (port_u8)(saved_hl >> 8);
	state->registers.l = (port_u8)saved_hl;
	state->registers.a = state->registers.l;
	front_add(&state->registers, 16);
	state->registers.l = state->registers.a;
	front_inc(&state->registers, &state->registers.e);
	front_dec(&state->registers, &state->registers.d);
	return state->registers.d == 0 ? 0 : 1;
}

/* Port of IsSpriteInFrontOfPlayer2 in home/overworld.asm. */
__attribute__((noinline, used)) void
port_is_sprite_in_front_of_player2(
	struct sprite_in_front_state *state, port_u8 *memory)
{
	port_u8 continuation = port_is_sprite_in_front_setup(state);
	port_u16 hl;

	while (continuation == 1) {
		hl = front_pair(state->registers.h, state->registers.l);
		state->sprite_image = memory[hl];
		state->sprite_visibility = memory[(port_u16)(hl + 2)];
		state->sprite_y = memory[(port_u16)(hl + 4)];
		state->sprite_x = memory[(port_u16)(hl + 6)];
		state->movement_status = memory[(port_u16)((hl & 0xfff0) + 1)];
		continuation = port_is_sprite_in_front_step(state);
		if (continuation == 2)
			memory[front_pair(state->registers.h, state->registers.l)] =
				state->movement_status;
	}
}
