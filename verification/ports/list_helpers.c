#include "port_state.h"

/* Port of InitializeEmptyList in engine/movie/oak_speech/init_player_data.asm. */
__attribute__((noinline, used)) void
port_initialize_empty_list(struct empty_list_state *state)
{
	port_u16 hl = ((port_u16)state->registers.h << 8) | state->registers.l;

	state->registers.a = 0;
	state->first = state->registers.a;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.a--;
	state->registers.f = PORT_FLAG_N | PORT_FLAG_H;
	state->terminator = state->registers.a;
}

static __attribute__((noinline)) void
overwrite_channel_pointer(struct empty_list_state *state)
{
	port_u16 hl = ((port_u16)state->registers.h << 8) | state->registers.l;

	state->registers.a = state->registers.e;
	state->first = state->registers.a;
	hl++;
	state->registers.a = state->registers.d;
	state->terminator = state->registers.a;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
}

/* Ports of the identical channel-pointer overwrite leaves. */
__attribute__((noinline, used)) void
port_audio1_overwrite_channel_pointer(struct empty_list_state *state)
{
	overwrite_channel_pointer(state);
}

__attribute__((noinline, used)) void
port_audio2_overwrite_channel_pointer(struct empty_list_state *state)
{
	overwrite_channel_pointer(state);
}

/* Port of ResetStatMods in engine/battle/move_effects/haze.asm. */
__attribute__((noinline, used)) void
port_reset_stat_mods(struct stat_mod_reset_state *state)
{
	port_u16 hl = ((port_u16)state->registers.h << 8) | state->registers.l;
	port_u8 index;

	state->registers.b = 8;
	for (index = 0; index < 8; index++) {
		state->modifiers[index] = state->registers.a;
		hl++;
		state->registers.b--;
	}
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.f =
		(state->registers.f & PORT_FLAG_C) | PORT_FLAG_Z | PORT_FLAG_N;
}

__attribute__((noinline, used)) port_u8
port_clear_sprites_begin(struct copy_string_step_state *state)
{
	state->registers.a = 0;
	state->registers.f = PORT_FLAG_Z;
	state->registers.h = 0xc3;
	state->registers.l = 0;
	state->registers.b = 0xa0;
	return 0;
}

__attribute__((noinline, used)) port_u8
port_clear_sprites_step(struct copy_string_step_state *state)
{
	port_u16 hl = ((port_u16)state->registers.h << 8) | state->registers.l;
	port_u8 previous_b = state->registers.b;
	port_u8 flags;

	state->written = state->registers.a;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	state->registers.b--;
	flags = (state->registers.f & PORT_FLAG_C) | PORT_FLAG_N;
	if (state->registers.b == 0)
		flags |= PORT_FLAG_Z;
	if ((previous_b & 0x0f) == 0)
		flags |= PORT_FLAG_H;
	state->registers.f = flags;
	return state->registers.b == 0;
}

/* Port of ClearSprites in home/clear_sprites.asm. */
__attribute__((noinline, used)) void
port_clear_sprites(struct clear_sprites_state *state)
{
	struct copy_string_step_state step;
	port_u8 index;

	step.registers = state->registers;
	port_clear_sprites_begin(&step);
	for (index = 0; index < 160; index++) {
		port_clear_sprites_step(&step);
		state->oam[index] = step.written;
	}
	state->registers = step.registers;
}

__attribute__((noinline, used)) void
port_hide_sprites_begin(struct copy_string_step_state *state)
{
	state->registers.a = 0xa0;
	state->registers.h = 0xc3;
	state->registers.l = 0;
	state->registers.d = 0;
	state->registers.e = 4;
	state->registers.b = 40;
}

__attribute__((noinline, used)) port_u8
port_hide_sprites_step(struct copy_string_step_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);
	port_u16 de = (port_u16)(((port_u16)state->registers.d << 8) |
		state->registers.e);
	port_u16 result = (port_u16)(hl + de);
	port_u8 old_b;

	state->written = state->registers.a;
	state->registers.f &= PORT_FLAG_Z;
	if ((hl & 0x0fff) + (de & 0x0fff) > 0x0fff)
		state->registers.f |= PORT_FLAG_H;
	if ((unsigned long)hl + de > 0xffff)
		state->registers.f |= PORT_FLAG_C;
	state->registers.h = (port_u8)(result >> 8);
	state->registers.l = (port_u8)result;
	old_b = state->registers.b;
	state->registers.b--;
	state->registers.f &= PORT_FLAG_C;
	state->registers.f |= PORT_FLAG_N;
	if (state->registers.b == 0)
		state->registers.f |= PORT_FLAG_Z;
	if ((old_b & 0x0f) == 0)
		state->registers.f |= PORT_FLAG_H;
	return state->registers.b == 0;
}

/* Port of HideSprites in home/clear_sprites.asm. */
__attribute__((noinline, used)) void
port_hide_sprites(struct clear_sprites_state *state)
{
	struct copy_string_step_state step;
	port_u8 index;

	step.registers = state->registers;
	port_hide_sprites_begin(&step);
	for (index = 0; index < 40; index++) {
		port_hide_sprites_step(&step);
		state->oam[index * 4] = step.written;
	}
	state->registers = step.registers;
}

static void
init_list_compare(struct cpu_register_state *registers, port_u8 right)
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

/* Port of InitList in engine/battle/misc.asm. */
__attribute__((noinline, used)) void
port_init_list(struct init_list_state *state)
{
	state->registers.a = state->init_list_type;
	init_list_compare(&state->registers, 1);
	if (state->registers.a == 1) {
		state->registers.h = 0xd8;
		state->registers.l = 0x9c;
		state->registers.d = 0xd9;
		state->registers.e = 0xac;
		state->registers.a = 6;
	} else {
		init_list_compare(&state->registers, 4);
		if (state->registers.a == 4) {
			state->registers.h = 0xd1;
			state->registers.l = 0x63;
			state->registers.d = 0xd2;
			state->registers.e = 0x73;
			state->registers.a = 5;
		} else {
			init_list_compare(&state->registers, 5);
			if (state->registers.a == 5) {
				state->registers.h = 0xcf;
				state->registers.l = 0x7b;
				state->registers.d = 0x42;
				state->registers.e = 0x1e;
				state->registers.a = 1;
			} else {
				init_list_compare(&state->registers, 2);
				if (state->registers.a == 2) {
					state->registers.h = 0xd3;
					state->registers.l = 0x1d;
				} else {
					state->registers.h = 0xcf;
					state->registers.l = 0x7b;
				}
				state->registers.d = 0x47;
				state->registers.e = 0x2b;
				state->registers.a = 4;
			}
		}
	}
	state->name_list_type = state->registers.a;
	state->registers.a = state->registers.l;
	state->list_pointer[0] = state->registers.a;
	state->registers.a = state->registers.h;
	state->list_pointer[1] = state->registers.a;
	state->registers.a = state->registers.e;
	state->unused_name_pointer[0] = state->registers.a;
	state->registers.a = state->registers.d;
	state->unused_name_pointer[1] = state->registers.a;
	state->registers.b = 0x46;
	state->registers.c = 0x08;
	state->registers.a = state->registers.c;
	state->item_prices[0] = state->registers.a;
	state->registers.a = state->registers.b;
	state->item_prices[1] = state->registers.a;
}
