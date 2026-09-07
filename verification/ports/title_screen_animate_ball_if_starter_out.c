#include "port_state.h"

void port_title_scroll_body(struct title_scroll_body_state *,
	const port_u8 *, const port_u8 *,
	const struct title_scroll_scanline_timing *);

#define W_TITLE_MON_SPECIES 0xcd3du
#define STARTER1 0xb0u
#define STARTER2 0xb1u
#define STARTER3 0x99u

static void
title_ball_cp(struct cpu_register_state *registers, port_u8 value)
{
	port_u8 left = registers->a;
	port_u8 result = (port_u8)(left - value);

	registers->f = PORT_FLAG_N;
	if (result == 0)
		registers->f |= PORT_FLAG_Z;
	if ((left & 0x0f) < (value & 0x0f))
		registers->f |= PORT_FLAG_H;
	if (left < value)
		registers->f |= PORT_FLAG_C;
}

/* Port of TitleScreenAnimateBallIfStarterOut in engine/movie/title2.asm. */
__attribute__((noinline, used)) void
port_title_screen_animate_ball_if_starter_out(
	struct title_scroll_body_state *state, const port_u8 *memory,
	const port_u8 *wait_table, const port_u8 *title_ball_y_table,
	const struct title_scroll_scanline_timing *timings)
{
	struct cpu_register_state *registers = &state->registers;

	registers->a = memory[W_TITLE_MON_SPECIES];
	title_ball_cp(registers, STARTER1);
	if (registers->a != STARTER1) {
		title_ball_cp(registers, STARTER2);
		if (registers->a != STARTER2) {
			title_ball_cp(registers, STARTER3);
			if (registers->a != STARTER3)
				return;
		}
	}

	registers->e = 1;
	registers->b = 0x72;
	registers->c = 0x44;
	registers->d = 0;
	port_title_scroll_body(state, wait_table, title_ball_y_table, timings);
}
