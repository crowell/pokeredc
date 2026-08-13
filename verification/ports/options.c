#include "port_state.h"

static void
options_cp_c(struct cpu_register_state *registers)
{
	port_u8 left = registers->a;
	port_u8 right = registers->c;

	registers->f = PORT_FLAG_N;
	if (left == right)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (right & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < right)
		registers->f |= PORT_FLAG_C;
}

static void
options_dec_a(struct cpu_register_state *registers)
{
	port_u8 old = registers->a;

	registers->a--;
	registers->f &= PORT_FLAG_C;
	registers->f |= PORT_FLAG_N;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

__attribute__((noinline, used)) void
port_set_options_from_cursor_positions_begin(struct option_cursor_state *state)
{
	state->registers.h = 0x60;
	state->registers.l = 0x96;
	state->registers.a = state->text_speed_cursor;
	state->registers.c = state->registers.a;
}

__attribute__((noinline, used)) port_u8
port_set_options_from_cursor_positions_step(struct option_cursor_state *state)
{
	port_u16 hl = (port_u16)(((port_u16)state->registers.h << 8) |
		state->registers.l);

	state->registers.a = state->fetched_compare;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	options_cp_c(&state->registers);
	if (state->registers.a == state->registers.c)
		return 1;
	hl++;
	state->registers.h = (port_u8)(hl >> 8);
	state->registers.l = (port_u8)hl;
	return 0;
}

__attribute__((noinline, used)) void
port_set_options_from_cursor_positions_finish(struct option_cursor_state *state)
{
	state->registers.a = state->fetched_value;
	state->registers.d = state->registers.a;
	state->registers.a = state->battle_animation_cursor;
	options_dec_a(&state->registers);
	if (state->registers.a == 0)
		state->registers.d &= (port_u8)~0x80;
	else
		state->registers.d |= 0x80;
	state->registers.a = state->battle_style_cursor;
	options_dec_a(&state->registers);
	if (state->registers.a == 0)
		state->registers.d &= (port_u8)~0x40;
	else
		state->registers.d |= 0x40;
	state->registers.a = state->registers.d;
	state->options = state->registers.a;
}

/* Port of SetOptionsFromCursorPositions in engine/menus/main_menu.asm. */
__attribute__((noinline, used)) void
port_set_options_from_cursor_positions(struct option_cursor_state *state,
	const port_u8 *table)
{
	port_u16 index = 0;

	port_set_options_from_cursor_positions_begin(state);
	for (;;) {
		state->fetched_compare = table[index];
		state->fetched_value = table[index + 1];
		if (port_set_options_from_cursor_positions_step(state))
			break;
		index = (port_u16)(index + 2);
	}
	port_set_options_from_cursor_positions_finish(state);
}
