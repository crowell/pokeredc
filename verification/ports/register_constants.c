#include "port_state.h"

/* Port of ExecuteEnemyMoveDone in engine/battle/core.asm. */
__attribute__((noinline, used)) void
port_execute_enemy_move_done(struct cpu_register_state *state)
{
	state->b = 1;
}

/* Port of TextScriptEnd in home/overworld_text.asm. */
__attribute__((noinline, used)) void
port_text_script_end(struct cpu_register_state *state)
{
	state->h = 0x24;
	state->l = 0xd6;
}

static __attribute__((noinline)) void
set_hl(struct cpu_register_state *state, port_u16 value)
{
	state->h = (port_u8)(value >> 8);
	state->l = (port_u8)value;
}

/* Ports of item-use failure entries that select text then share a tail. */
__attribute__((noinline, used)) void
port_item_use_no_effect(struct cpu_register_state *state)
{
	set_hl(state, 0x65ca);
}

__attribute__((noinline, used)) void
port_item_use_not_time(struct cpu_register_state *state)
{
	set_hl(state, 0x65c0);
}

__attribute__((noinline, used)) void
port_item_use_not_yours_to_use(struct cpu_register_state *state)
{
	set_hl(state, 0x65c5);
}

__attribute__((noinline, used)) void
port_no_cycling_allowed_here(struct cpu_register_state *state)
{
	set_hl(state, 0x65d9);
}

__attribute__((noinline, used)) void
port_box_full_cannot_throw_ball(struct cpu_register_state *state)
{
	set_hl(state, 0x65e3);
}

__attribute__((noinline, used)) void
port_surfing_attempt_failed(struct cpu_register_state *state)
{
	set_hl(state, 0x65de);
}

void port_delay_frames(struct delay_frame_state *state,
	const port_u8 *observations);

static __attribute__((noinline)) void
fade_delay_frames(struct cpu_register_state *state, port_u8 count)
{
	static const port_u8 acknowledged_vblank[] = { 0 };
	struct delay_frame_state delay;

	state->c = count;
	delay.registers = *state;
	delay.vblank_occurred = 0;
	delay.observed_vblank = 0;
	port_delay_frames(&delay, acknowledged_vblank);
	*state = delay.registers;
}

static __attribute__((noinline)) port_u8
fade_dec_b(struct cpu_register_state *state)
{
	port_u8 before = state->b;
	port_u8 result = (port_u8)(before - 1);
	port_u8 flags = (port_u8)((state->f & PORT_FLAG_C) | PORT_FLAG_N);

	if (result == 0)
		flags |= PORT_FLAG_Z;
	if ((before & 0x0f) == 0)
		flags |= PORT_FLAG_H;
	state->b = result;
	state->f = flags;
	return result != 0;
}

/* Complete port of GBFadeInFromBlack in home/fade.asm. */
__attribute__((noinline, used)) void
port_gb_fade_in_from_black(struct cpu_register_state *state, port_u8 *memory)
{
	set_hl(state, 0x210d);
	state->b = 4;
	do {
		port_u16 hl = ((port_u16)state->h << 8) | state->l;

		state->a = memory[hl++];
		memory[0xff47] = state->a;
		state->a = memory[hl++];
		memory[0xff48] = state->a;
		state->a = memory[hl++];
		memory[0xff49] = state->a;
		state->h = (port_u8)(hl >> 8);
		state->l = (port_u8)hl;
		fade_delay_frames(state, 8);
	} while (fade_dec_b(state));
}

/* Complete port of GBFadeOutToWhite in home/fade.asm. */
__attribute__((noinline, used)) void
port_gb_fade_out_to_white(struct cpu_register_state *state, port_u8 *memory)
{
	set_hl(state, 0x211c);
	state->b = 3;
	do {
		port_u16 hl = ((port_u16)state->h << 8) | state->l;

		state->a = memory[hl++];
		memory[0xff47] = state->a;
		state->a = memory[hl++];
		memory[0xff48] = state->a;
		state->a = memory[hl++];
		memory[0xff49] = state->a;
		state->h = (port_u8)(hl >> 8);
		state->l = (port_u8)hl;
		fade_delay_frames(state, 8);
	} while (fade_dec_b(state));
}

/* Remaining decrementing fade entries stop at their shared-loop boundary. */
__attribute__((noinline, used)) void
port_gb_fade_out_to_black(struct cpu_register_state *state)
{
	set_hl(state, 0x2118);
	state->b = 4;
}

__attribute__((noinline, used)) void
port_gb_fade_in_from_white(struct cpu_register_state *state)
{
	set_hl(state, 0x2121);
	state->b = 3;
}

static __attribute__((noinline)) void
set_de_hl(struct cpu_register_state *state, port_u16 de, port_u16 hl)
{
	state->d = (port_u8)(de >> 8);
	state->e = (port_u8)de;
	state->h = (port_u8)(hl >> 8);
	state->l = (port_u8)hl;
}

/* Ports of player-sprite graphics entries through their shared tail. */
__attribute__((noinline, used)) void
port_load_walking_player_sprite_graphics(struct cpu_register_state *state)
{
	set_de_hl(state, 0x4180, 0x8000);
}

__attribute__((noinline, used)) void
port_load_surfing_player_sprite_graphics(struct cpu_register_state *state)
{
	set_de_hl(state, 0x76c0, 0x8000);
}

__attribute__((noinline, used)) void
port_load_bike_player_sprite_graphics(struct cpu_register_state *state)
{
	set_de_hl(state, 0x4000, 0x8000);
}

/* Ports of sprite-position entries through the bankswitch boundary. */
__attribute__((noinline, used)) void
port_get_sprite_position1(struct cpu_register_state *state)
{
	set_hl(state, 0x67f9);
}

__attribute__((noinline, used)) void
port_get_sprite_position2(struct cpu_register_state *state)
{
	set_hl(state, 0x6819);
}

__attribute__((noinline, used)) void
port_set_sprite_position1(struct cpu_register_state *state)
{
	set_hl(state, 0x683d);
}

__attribute__((noinline, used)) void
port_set_sprite_position2(struct cpu_register_state *state)
{
	set_hl(state, 0x685d);
}

/* Ports of party-menu entries through their shared bankswitch boundary. */
__attribute__((noinline, used)) void
port_draw_party_menu(struct cpu_register_state *state)
{
	set_hl(state, 0x6cd2);
}

__attribute__((noinline, used)) void
port_redraw_party_menu(struct cpu_register_state *state)
{
	set_hl(state, 0x6ce3);
}

/* Small register-only entries through their shared implementation tails. */
__attribute__((noinline, used)) void
port_is_in_array(struct cpu_register_state *state)
{
	state->b = 0;
}

__attribute__((noinline, used)) void
port_copy_to_string_buffer(struct cpu_register_state *state)
{
	set_hl(state, 0xcf4b);
}

__attribute__((noinline, used)) void
port_run_default_palette_command(struct cpu_register_state *state)
{
	state->b = 0xff;
}

__attribute__((noinline, used)) void
port_get_pointer_within_sprite_state_data1(struct cpu_register_state *state)
{
	state->h = 0xc1;
}

__attribute__((noinline, used)) void
port_get_pointer_within_sprite_state_data2(struct cpu_register_state *state)
{
	state->h = 0xc2;
}

__attribute__((noinline, used)) void
port_is_sprite_in_front_of_player(struct cpu_register_state *state)
{
	state->d = 0x10;
}

__attribute__((noinline, used)) void
port_change_facing_direction(struct cpu_register_state *state)
{
	state->d = 0;
	state->e = 0;
}

__attribute__((noinline, used)) void
port_clear_bg_map(struct cpu_register_state *state)
{
	state->a = 0x7f;
}

__attribute__((noinline, used)) void
port_intro_clear_screen(struct cpu_register_state *state)
{
	state->h = 0x9c;
	state->l = 0;
	state->b = 0x02;
	state->c = 0x40;
}

__attribute__((noinline, used)) void
port_intro_clear_middle_of_screen(struct cpu_register_state *state)
{
	state->h = 0xc3;
	state->l = 0xf0;
	state->b = 0;
	state->c = 0xc8;
}

__attribute__((noinline, used)) void
port_intro_copy_tiles(struct cpu_register_state *state)
{
	state->h = 0xc4;
	state->l = 0x39;
}

static void
set_ab(struct cpu_register_state *state, port_u8 a, port_u8 b)
{
	state->a = a;
	state->b = b;
}

__attribute__((noinline, used)) void port_ai_use_potion(struct cpu_register_state *state) { set_ab(state, 0x14, 20); }
__attribute__((noinline, used)) void port_ai_use_super_potion(struct cpu_register_state *state) { set_ab(state, 0x13, 50); }
__attribute__((noinline, used)) void port_ai_use_hyper_potion(struct cpu_register_state *state) { set_ab(state, 0x12, 200); }
__attribute__((noinline, used)) void port_ai_use_x_attack(struct cpu_register_state *state) { set_ab(state, 0x41, 0x0a); }
__attribute__((noinline, used)) void port_ai_use_x_defend(struct cpu_register_state *state) { set_ab(state, 0x42, 0x0b); }
__attribute__((noinline, used)) void port_ai_use_x_speed(struct cpu_register_state *state) { set_ab(state, 0x43, 0x0c); }
__attribute__((noinline, used)) void port_ai_use_x_special(struct cpu_register_state *state) { set_ab(state, 0x44, 0x0d); }
__attribute__((noinline, used)) void port_get_sprite_screen_y_pointer(struct cpu_register_state *state) { set_ab(state, 4, 4); }
__attribute__((noinline, used)) void port_get_sprite_screen_x_pointer(struct cpu_register_state *state) { set_ab(state, 6, 6); }

__attribute__((noinline, used)) port_u8
port_add_n_times_begin(struct cpu_register_state *state)
{
	state->f = PORT_FLAG_H;
	if (state->a == 0)
		state->f |= PORT_FLAG_Z;
	return state->a == 0;
}

__attribute__((noinline, used)) port_u8
port_add_n_times_step(struct cpu_register_state *state)
{
	port_u16 hl = ((port_u16)state->h << 8) | state->l;
	port_u16 bc = ((port_u16)state->b << 8) | state->c;
	unsigned long wide = (unsigned long)hl + bc;
	port_u8 previous_a;
	port_u8 flags = wide > 0xffff ? PORT_FLAG_C : 0;

	state->h = (port_u8)(wide >> 8);
	state->l = (port_u8)wide;
	previous_a = state->a;
	state->a--;
	flags |= PORT_FLAG_N;
	if (state->a == 0)
		flags |= PORT_FLAG_Z;
	if ((previous_a & 0x0f) == 0)
		flags |= PORT_FLAG_H;
	state->f = flags;
	return state->a == 0;
}

/* Port of AddNTimes in home/array.asm. */
__attribute__((noinline, used)) void
port_add_n_times(struct cpu_register_state *state)
{
	if (port_add_n_times_begin(state))
		return;
	while (!port_add_n_times_step(state))
		;
}

__attribute__((noinline, used)) port_u8
port_skip_fixed_length_text_entries_begin(struct cpu_register_state *state)
{
	if (port_add_n_times_begin(state))
		return 1;
	state->b = 0;
	state->c = 11;
	return 0;
}

/* Port of SkipFixedLengthTextEntries in home/array.asm. */
__attribute__((noinline, used)) void
port_skip_fixed_length_text_entries(struct cpu_register_state *state)
{
	if (port_skip_fixed_length_text_entries_begin(state))
		return;
	while (!port_add_n_times_step(state))
		;
}
