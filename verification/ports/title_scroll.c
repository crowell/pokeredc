#include "port_state.h"

void port_title_scroll_scroll_between(struct scanline_scx_state *,
	const port_u8 *, const port_u8 *);
void port_get_title_ball_y(struct title_ball_y_state *);

static void
title_scroll_and(struct cpu_register_state *registers, port_u8 value)
{
	registers->a &= value;
	registers->f = PORT_FLAG_H;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
}

static void
title_scroll_swap_a(struct cpu_register_state *registers)
{
	registers->a = (port_u8)((registers->a << 4) |
		(registers->a >> 4));
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
}

static void
title_scroll_add_b(struct cpu_register_state *registers)
{
	port_u8 left = registers->a;
	port_u8 right = registers->b;
	port_u16 result = (port_u16)left + right;

	registers->a = (port_u8)result;
	registers->f = 0;
	if (registers->a == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) + (right & 0x0f) > 0x0f)
		registers->f |= PORT_FLAG_H;
	if (result > 0xff)
		registers->f |= PORT_FLAG_C;
}

static void
title_scroll_dec_c(struct cpu_register_state *registers)
{
	port_u8 old = registers->c;

	registers->c--;
	registers->f &= PORT_FLAG_C;
	registers->f |= PORT_FLAG_N;
	if (registers->c == 0)
		registers->f |= PORT_FLAG_Z;
	if ((old & 0x0f) == 0)
		registers->f |= PORT_FLAG_H;
}

static void
title_scroll_between(struct title_scroll_body_state *state,
	const struct title_scroll_scanline_timing *timing)
{
	struct scanline_scx_state scanline;

	scanline.registers = state->registers;
	scanline.ly = state->ly;
	scanline.scx = state->scx;
	port_title_scroll_scroll_between(&scanline, timing->before,
		timing->after);
	state->registers = scanline.registers;
	state->ly = scanline.ly;
	state->scx = scanline.scx;
}

static void
title_scroll_get_ball_y(struct title_scroll_body_state *state,
	const port_u8 *title_ball_y_table)
{
	struct title_ball_y_state ball;

	ball.registers = state->registers;
	ball.output_y = state->title_ball_y;
	ball.fetched = title_ball_y_table[state->registers.e];
	port_get_title_ball_y(&ball);
	state->registers = ball.registers;
	state->title_ball_y = ball.output_y;
}

/* Port of TitleScroll's entry dispatcher in engine/movie/title2.asm. */
__attribute__((noinline, used)) void
port_title_scroll(struct cpu_register_state *state)
{
	state->a = state->d;
	state->b = 0x72;
	state->c = 0x47;
	state->d = 0x88;
	state->e = 0;
	state->f = PORT_FLAG_H;
	if (state->a == 0) {
		state->f |= PORT_FLAG_Z;
		state->b = 0x72;
		state->c = 0x4f;
		state->d = 0;
		state->e = 0;
	}
}

/* Port of _TitleScroll in engine/movie/title2.asm. */
__attribute__((noinline, used)) void
port_title_scroll_body(struct title_scroll_body_state *state,
	const port_u8 *scroll_table, const port_u8 *title_ball_y_table,
	const struct title_scroll_scanline_timing *timings)
{
	struct cpu_register_state *registers = &state->registers;
	port_u16 table_index = 0;
	port_u16 timing_index = 0;

	for (;;) {
		port_u8 saved_b;
		port_u8 saved_c;
		port_u16 bc;

		registers->a = scroll_table[table_index];
		title_scroll_and(registers, 0xff);
		if (registers->a == 0)
			return;

		bc = (port_u16)(((port_u16)registers->b << 8) |
			registers->c);
		bc++;
		registers->b = (port_u8)(bc >> 8);
		registers->c = (port_u8)bc;
		table_index++;
		saved_b = registers->b;
		saved_c = registers->c;

		registers->b = registers->a;
		title_scroll_and(registers, 0x0f);
		registers->c = registers->a;
		registers->a = registers->b;
		title_scroll_and(registers, 0xf0);
		title_scroll_swap_a(registers);
		registers->b = registers->a;

		do {
			registers->h = registers->d;
			registers->l = 0x48;
			title_scroll_between(state, &timings[timing_index++]);
			registers->h = 0;
			registers->l = 0x88;
			title_scroll_between(state, &timings[timing_index++]);
			registers->a = registers->d;
			title_scroll_add_b(registers);
			registers->d = registers->a;
			title_scroll_get_ball_y(state, title_ball_y_table);
			title_scroll_dec_c(registers);
		} while (registers->c != 0);

		registers->b = saved_b;
		registers->c = saved_c;
	}
}
